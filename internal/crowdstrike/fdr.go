package crowdstrike

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/rs/zerolog"

	"github.com/youruser/crowdstrike-wazuh-bridge/internal/models"
)

// FDRConsumer implements CrowdStrike's standard Falcon Data Replicator pattern:
// CrowdStrike drops gzipped NDJSON files into a CrowdStrike-owned S3 bucket and
// publishes a notification message to an SQS queue that CrowdStrike provisions
// for your CID. We long-poll the queue, download+decompress each referenced
// file, emit every event, then delete the SQS message (not the S3 object --
// CrowdStrike manages retention on their bucket).
type FDRConsumer struct {
	sqsClient *sqs.Client
	s3Client  *s3.Client
	queueURL  string
	logger    zerolog.Logger
}

func NewFDRConsumer(ctx context.Context, region, queueURL, accessKeyID, secretAccessKey string, logger zerolog.Logger) (*FDRConsumer, error) {
	var cfgOpts []func(*awsconfig.LoadOptions) error
	cfgOpts = append(cfgOpts, awsconfig.WithRegion(region))
	if accessKeyID != "" && secretAccessKey != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config for FDR: %w", err)
	}

	return &FDRConsumer{
		sqsClient: sqs.NewFromConfig(awsCfg),
		s3Client:  s3.NewFromConfig(awsCfg),
		queueURL:  queueURL,
		logger:    logger.With().Str("component", "fdr").Logger(),
	}, nil
}

type fdrNotification struct {
	Bucket     string   `json:"bucket"`
	PathPrefix string   `json:"pathPrefix"`
	Files      []string `json:"files"`
	FileCount  int      `json:"fileCount"`
}

// Run long-polls the SQS queue forever, processing each notification.
func (f *FDRConsumer) Run(ctx context.Context, handle EventHandler) error {
	receiveFailures := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		out, err := f.sqsClient.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl:            aws.String(f.queueURL),
			MaxNumberOfMessages: 10,
			WaitTimeSeconds:     20, // long poll
			VisibilityTimeout:   300,
		})
		if err != nil {
			receiveFailures++
			delay := retryDelay(defaultRetryPolicy, receiveFailures)
			f.logger.Warn().Err(err).Dur("retry_in", delay).Msg("SQS receive failed; retrying")
			if err := waitForRetry(ctx, delay); err != nil {
				return err
			}
			continue
		}
		receiveFailures = 0

		for _, msg := range out.Messages {
			if err := f.processMessage(ctx, msg.Body, handle); err != nil {
				f.logger.Warn().Err(err).Msg("failed to process FDR message; leaving it for redelivery")
				continue
			}
			if msg.ReceiptHandle != nil {
				if _, err := f.sqsClient.DeleteMessage(ctx, &sqs.DeleteMessageInput{
					QueueUrl:      aws.String(f.queueURL),
					ReceiptHandle: msg.ReceiptHandle,
				}); err != nil && ctx.Err() == nil {
					f.logger.Warn().Err(err).Msg("failed to delete processed FDR message")
				}
			}
		}
	}
}

func (f *FDRConsumer) processMessage(ctx context.Context, body *string, handle EventHandler) error {
	if body == nil {
		return nil
	}
	var note fdrNotification
	if err := json.Unmarshal([]byte(*body), &note); err != nil {
		return fmt.Errorf("decoding FDR notification: %w", err)
	}

	var processErr error
	for _, key := range note.Files {
		if err := f.processObject(ctx, note.Bucket, key, handle); err != nil {
			f.logger.Warn().Err(err).Str("bucket", note.Bucket).Str("key", key).Msg("failed to process FDR object")
			// Process the remaining files, then keep the SQS message so failed
			// objects can be redelivered instead of being silently lost.
			processErr = err
		}
	}
	return processErr
}

func (f *FDRConsumer) processObject(ctx context.Context, bucket, key string, handle EventHandler) error {
	out, err := f.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("s3 GetObject: %w", err)
	}
	defer out.Body.Close()

	var reader = bufio.NewReader(out.Body)
	// FDR objects are gzip-compressed NDJSON.
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	scanner := bufio.NewScanner(gz)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	count := 0
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		ev, err := parseFDRLine(line)
		if err != nil {
			return fmt.Errorf("parsing FDR object %s line %d: %w", key, lineNumber, err)
		}
		if err := handle(ev); err != nil {
			return fmt.Errorf("handling FDR event: %w", err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading FDR object: %w", err)
	}
	f.logger.Info().Int("event_count", count).Str("bucket", bucket).Str("key", key).Msg("processed FDR object")
	return nil
}

func parseFDRLine(line string) (models.Event, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return models.Event{}, err
	}

	ev := models.Event{
		Source:     models.SourceFDR,
		IngestedAt: time.Now().UTC(),
		OccurredAt: time.Now().UTC(),
		RawPayload: []byte(line),
		Raw:        raw,
	}

	if et, ok := raw["event_simpleName"].(string); ok {
		ev.EventType = et
	}
	if aid, ok := raw["aid"].(string); ok {
		ev.AID = aid
	}
	if host, ok := raw["ComputerName"].(string); ok {
		ev.Hostname = host
	}
	if ts, ok := raw["timestamp"].(float64); ok {
		ev.OccurredAt = time.UnixMilli(int64(ts)).UTC()
	}

	return ev, nil
}

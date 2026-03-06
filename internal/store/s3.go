package store

import (
	"context"
	"errors"
	"io"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// AWSS3Client implements S3Client using AWS SDK v2.
// Credentials are resolved via the default chain: environment variables,
// shared credentials file (~/.aws/credentials), IAM roles, etc.
type AWSS3Client struct {
	client *s3.Client
}

// NewAWSS3Client creates an S3 client for the given region.
func NewAWSS3Client(ctx context.Context, region string) (*AWSS3Client, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return &AWSS3Client{client: s3.NewFromConfig(cfg)}, nil
}

func (c *AWSS3Client) Upload(ctx context.Context, bucket, key string, body io.Reader) error {
	_, err := c.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   body,
	})
	return err
}

func (c *AWSS3Client) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	out, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}

func (c *AWSS3Client) Delete(ctx context.Context, bucket, key string) error {
	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	return err
}

// Exists checks if an object exists in S3 using HeadObject.
func (c *AWSS3Client) Exists(ctx context.Context, bucket, key string) (bool, error) {
	_, err := c.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		var nf *types.NotFound
		if errors.As(err, &nf) {
			return false, nil
		}
		// Some S3-compatible services return NoSuchKey via generic API error
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			code := apiErr.ErrorCode()
			if code == "NotFound" || code == "NoSuchKey" || code == "404" {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}

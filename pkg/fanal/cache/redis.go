package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/hashicorp/go-multierror"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var _ Cache = &RedisCache{}

const (
	redisPrefix = "fanal"
)

type RedisCache struct {
	client     *redis.Client
	expiration time.Duration
}

func NewRedisCache(options *redis.Options, expiration time.Duration) RedisCache {
	return RedisCache{
		client:     redis.NewClient(options),
		expiration: expiration,
	}
}

func (c RedisCache) PutArtifact(artifactID string, artifactConfig types.ArtifactInfo) error {
	key := fmt.Sprintf("%s::%s::%s", redisPrefix, artifactBucket, artifactID)
	b, err := json.Marshal(artifactConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal artifact JSON: %w", err)
	}
	if err := c.client.Set(context.TODO(), key, string(b), c.expiration).Err(); err != nil {
		return fmt.Errorf("unable to store artifact information in Redis cache (%s): %w", artifactID, err)
	}
	return nil
}

func (c RedisCache) PutBlob(blobID string, blobInfo types.BlobInfo) error {
	b, err := json.Marshal(blobInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal blob JSON: %w", err)
	}
	key := fmt.Sprintf("%s::%s::%s", redisPrefix, blobBucket, blobID)
	if err := c.client.Set(context.TODO(), key, string(b), c.expiration).Err(); err != nil {
		return fmt.Errorf("unable to store blob information in Redis cache (%s): %w", blobID, err)
	}
	return nil
}
func (c RedisCache) DeleteBlobs(blobIDs []string) error {
	var errs error
	for _, blobID := range blobIDs {
		key := fmt.Sprintf("%s::%s::%s", redisPrefix, artifactBucket, blobID)
		if err := c.client.Del(context.TODO(), key).Err(); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("unable to delete blob %s: %w", blobID, err))
		}
	}
	return errs
}

func (c RedisCache) GetArtifact(artifactID string) (types.ArtifactInfo, error) {
	key := fmt.Sprintf("%s::%s::%s", redisPrefix, artifactBucket, artifactID)
	val, err := c.client.Get(context.TODO(), key).Bytes()
	if err == redis.Nil {
		return types.ArtifactInfo{}, fmt.Errorf("artifact (%s) is missing in Redis cache", artifactID)
	} else if err != nil {
		return types.ArtifactInfo{}, fmt.Errorf("failed to get artifact from the Redis cache: %w", err)
	}

	var info types.ArtifactInfo
	err = json.Unmarshal(val, &info)
	if err != nil {
		return types.ArtifactInfo{}, fmt.Errorf("failed to unmarshal artifact (%s) from Redis value: %w", artifactID, err)
	}
	return info, nil
}

func (c RedisCache) GetBlob(blobID string) (types.BlobInfo, error) {
	key := fmt.Sprintf("%s::%s::%s", redisPrefix, blobBucket, blobID)
	val, err := c.client.Get(context.TODO(), key).Bytes()
	if err == redis.Nil {
		return types.BlobInfo{}, fmt.Errorf("blob (%s) is missing in Redis cache", blobID)
	} else if err != nil {
		return types.BlobInfo{}, fmt.Errorf("failed to get blob from the Redis cache: %w", err)
	}

	var blobInfo types.BlobInfo
	if err = json.Unmarshal(val, &blobInfo); err != nil {
		return types.BlobInfo{}, fmt.Errorf("failed to unmarshal blob (%s) from Redis value: %w", blobID, err)
	}
	return blobInfo, nil
}

func (c RedisCache) MissingBlobs(artifactID string, blobIDs []string) (bool, []string, error) {
	var missingArtifact bool
	var missingBlobIDs []string
	for _, blobID := range blobIDs {
		blobInfo, err := c.GetBlob(blobID)
		if err != nil {
			// error means cache missed blob info
			missingBlobIDs = append(missingBlobIDs, blobID)
			continue
		}
		if blobInfo.SchemaVersion != types.BlobJSONSchemaVersion {
			missingBlobIDs = append(missingBlobIDs, blobID)
		}
	}
	// get artifact info
	artifactInfo, err := c.GetArtifact(artifactID)
	// error means cache missed artifact info
	if err != nil {
		return true, missingBlobIDs, nil
	}
	if artifactInfo.SchemaVersion != types.ArtifactJSONSchemaVersion {
		missingArtifact = true
	}
	return missingArtifact, missingBlobIDs, nil
}

func (c RedisCache) Close() error {
	return c.client.Close()
}

func (c RedisCache) Clear() error {
	ctx := context.Background()

	for {
		keys, cursor, err := c.client.Scan(ctx, 0, redisPrefix+"::*", 100).Result()
		if err != nil {
			return fmt.Errorf("failed to perform prefix scanning: %w", err)
		}
		if err = c.client.Unlink(ctx, keys...).Err(); err != nil {
			return fmt.Errorf("failed to unlink redis keys: %w", err)
		}
		if cursor == 0 { // We cleared all keys
			break
		}
	}
	return nil
}

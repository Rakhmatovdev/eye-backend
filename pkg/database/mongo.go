package database

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// NewMongoDatabase connects to MongoDB (e.g. Atlas) and returns a handle to the
// given database. Call db.Client().Disconnect(ctx) on shutdown.
func NewMongoDatabase(ctx context.Context, uri, dbName string, log *zap.Logger) (*mongo.Database, error) {
	connectCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	opts := options.Client().
		ApplyURI(uri).
		SetMaxPoolSize(25).
		SetMinPoolSize(5).
		SetServerSelectionTimeout(15 * time.Second).
		SetAppName("intelligence-platform")

	client, err := mongo.Connect(connectCtx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mongo: %w", err)
	}

	if err := client.Ping(connectCtx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("failed to ping mongo: %w", err)
	}

	log.Info("MongoDB connected", zap.String("database", dbName))
	return client.Database(dbName), nil
}

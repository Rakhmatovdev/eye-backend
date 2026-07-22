package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"time"

	"intelligence-platform/pkg/pagination"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

type Service struct {
	db  *mongo.Database
	log *zap.Logger
}

func NewService(db *mongo.Database, log *zap.Logger) *Service {
	return &Service{db: db, log: log}
}

func (s *Service) col() *mongo.Collection      { return s.db.Collection("audit_logs") }
func (s *Service) counters() *mongo.Collection { return s.db.Collection("counters") }

// nextSeq atomically increments and returns the named counter.
func (s *Service) nextSeq(ctx context.Context, name string) (int64, error) {
	var res struct {
		Seq int64 `bson:"seq"`
	}
	opts := options.FindOneAndUpdate().
		SetUpsert(true).
		SetReturnDocument(options.After)
	err := s.counters().FindOneAndUpdate(ctx,
		bson.M{"_id": name},
		bson.M{"$inc": bson.M{"seq": int64(1)}},
		opts,
	).Decode(&res)
	if err != nil {
		return 0, err
	}
	return res.Seq, nil
}

func (s *Service) Log(ctx context.Context, userID, action, resource, ip, result string) error {
	// Get the previous hash from the most recent record.
	lastHash := zeroHash
	var last AuditLog
	err := s.col().FindOne(ctx, bson.M{}, options.FindOne().SetSort(bson.D{{Key: "id", Value: -1}})).Decode(&last)
	if err == nil {
		lastHash = last.Hash
	}

	ts := time.Now()
	data := fmt.Sprintf("%s:%s:%s:%s:%s:%s", userID, action, resource, ip, result, ts.Format(time.RFC3339))
	hasher := sha256.New()
	hasher.Write([]byte(data + lastHash))
	newHash := fmt.Sprintf("%x", hasher.Sum(nil))

	seq, err := s.nextSeq(ctx, "audit_logs")
	if err != nil {
		s.log.Error("Failed to get audit sequence", zap.Error(err))
		return err
	}

	entry := AuditLog{
		ID:        seq,
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		IP:        ip,
		Result:    result,
		Hash:      newHash,
		PrevHash:  lastHash,
		Timestamp: ts,
	}
	if _, err := s.col().InsertOne(ctx, entry); err != nil {
		s.log.Error("Failed to write audit log", zap.Error(err))
		return err
	}
	return nil
}

// List returns audit log entries matching the optional search/action
// filters. When pg is nil, the old fixed cap of 100 most-recent entries is
// returned (pre-pagination behaviour, total is 0 and should be ignored);
// otherwise a single page plus the total match count is returned.
func (s *Service) List(ctx context.Context, search, action string, pg *pagination.Params) ([]*AuditLog, int64, error) {
	filter := bson.M{}
	if search != "" {
		// QuoteMeta: the search term is a literal, never a user-supplied
		// regex (prevents ReDoS / pattern injection).
		rx := bson.M{"$regex": regexp.QuoteMeta(search), "$options": "i"}
		filter["$or"] = bson.A{
			bson.M{"user_id": rx},
			bson.M{"action": rx},
		}
	}
	if action != "" {
		filter["action"] = action
	}

	opts := options.Find().SetSort(bson.D{{Key: "ts", Value: -1}})
	var total int64
	if pg != nil {
		var err error
		total, err = s.col().CountDocuments(ctx, filter)
		if err != nil {
			return nil, 0, err
		}
		opts.SetSkip(pg.Skip()).SetLimit(pg.Take())
	} else {
		opts.SetLimit(100)
	}

	cur, err := s.col().Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cur.Close(ctx)

	logs := []*AuditLog{}
	if err := cur.All(ctx, &logs); err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

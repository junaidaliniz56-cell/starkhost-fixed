package main

// MongoDB persistence: accounts, projects, plans, keys, payments, settings and the
// server secret are mirrored to MongoDB, so they survive updates, redeploys and
// hosts whose disk is wiped. The local files in DATA_DIR stay as a second copy.
//
// Which MongoDB is used (first one that is set):
//   MONGO_URI        (+ MONGO_URI_PASSWORD  if the URI contains <db_password>)
//   ADMIN_DB_MONGO   (+ ADMIN_DB_MONGO_PASSWORD)   <- your existing Atlas settings
// If none is set, everything works as before (local files only).

import (
	"context"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	mcl   *mongo.Client
	mcol  *mongo.Collection
	pmu   sync.Mutex
	pend  = map[string]string{}
	pkick = make(chan struct{}, 1)
)

func mongoStateURI() string {
	for _, k := range []string{"MONGO_URI", "ADMIN_DB_MONGO"} {
		uri := strings.TrimSpace(os.Getenv(k))
		if uri == "" {
			continue
		}
		if strings.Contains(uri, "<db_password>") {
			if pw := os.Getenv(k + "_PASSWORD"); pw != "" {
				uri = strings.ReplaceAll(uri, "<db_password>", url.QueryEscape(pw))
			}
		}
		if strings.Contains(uri, "<") {
			log.Printf("MongoDB persistence: %s still contains <db_password> — set %s_PASSWORD in .env", k, k)
			continue
		}
		return uri
	}
	return ""
}

// mongoInit connects before the store is loaded. If a MongoDB is configured but cannot be
// reached the panel stops (and is restarted by Docker) instead of creating accounts that would be lost.
func mongoInit() {
	uri := mongoStateURI()
	if uri == "" {
		log.Println("MongoDB persistence: OFF (set MONGO_URI or ADMIN_DB_MONGO in .env to keep accounts across updates)")
		return
	}
	var err error
	for i := 1; i <= 6; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		var c *mongo.Client
		c, err = mongo.Connect(ctx, options.Client().ApplyURI(uri))
		if err == nil {
			err = c.Ping(ctx, nil)
		}
		cancel()
		if err == nil {
			mcl = c
			break
		}
		log.Printf("MongoDB persistence: connect attempt %d/6 failed: %v", i, err)
		time.Sleep(4 * time.Second)
	}
	if mcl == nil {
		log.Fatalf("MongoDB persistence: cannot connect (%v). Fix MONGO_URI / ADMIN_DB_MONGO (and Atlas Network Access = allow server IP) or remove it.", err)
	}
	mcol = mcl.Database("starkhost_panel").Collection("panel_data")
	log.Println("MongoDB persistence: ON — accounts and settings are saved in MongoDB")

	go func() {
		for range pkick {
			time.Sleep(400 * time.Millisecond)
			flushUp()
		}
	}()
	go func() { // on stop / restart / update: send anything still waiting to MongoDB first
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		flushUp()
		os.Exit(0)
	}()
}

// syncDown: if MongoDB already has this key, write it to the local file (MongoDB is the source of truth).
func syncDown(key, path string) {
	if mcol == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var doc struct {
		V string `bson:"v"`
	}
	err := mcol.FindOne(ctx, bson.M{"_id": key}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return // nothing in MongoDB yet: the local file (if any) will be uploaded on the next save
	}
	if err != nil {
		log.Fatalf("MongoDB persistence: cannot read %q: %v", key, err)
	}
	if doc.V == "" {
		return
	}
	if e := os.WriteFile(path, []byte(doc.V), 0600); e != nil {
		log.Printf("MongoDB persistence: cannot write %s: %v", path, e)
	}
}

// syncUp: queue a value to be saved in MongoDB (latest value per key wins).
func syncUp(key string, b []byte) {
	if mcol == nil {
		return
	}
	pmu.Lock()
	pend[key] = string(b)
	pmu.Unlock()
	select {
	case pkick <- struct{}{}:
	default:
	}
}

// pushLocal uploads a local file once at start-up if MongoDB does not have it yet.
func pushLocal(key, path string) {
	if mcol == nil {
		return
	}
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		syncUp(key, b)
	}
}

func flushUp() {
	if mcol == nil {
		return
	}
	pmu.Lock()
	batch := pend
	pend = map[string]string{}
	pmu.Unlock()
	for k, v := range batch {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, err := mcol.ReplaceOne(ctx, bson.M{"_id": k},
			bson.M{"_id": k, "v": v, "t": time.Now().Unix()},
			options.Replace().SetUpsert(true))
		cancel()
		if err != nil {
			log.Printf("MongoDB persistence: save %q failed (will retry): %v", k, err)
			pmu.Lock()
			if _, newer := pend[k]; !newer {
				pend[k] = v
			}
			pmu.Unlock()
			time.AfterFunc(5*time.Second, func() {
				select {
				case pkick <- struct{}{}:
				default:
				}
			})
		}
	}
}

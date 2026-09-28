package controlplane

import (
	"context"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"strings"
)

const AppsPath = "/api/management/apps"

type appRecord struct {
	ID             string `json:"id"`
	OwnerAccountID string `json:"-"`
	Name           string `json:"name"`
	Version        int64  `json:"version"`
}

func (appRecord) TableName() string { return "apps" }
func appETag(version int64) string  { return fmt.Sprintf(`"app-%d"`, version) }
func (store *Store) app(ctx context.Context, owner, id string) (appRecord, error) {
	var row appRecord
	err := store.db.WithContext(ctx).First(&row, "id = ? AND owner_account_id = ?", id, owner).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = failure(404, "app_not_found")
	}
	return row, err
}
func (management *Management) readApps(ctx *gin.Context, owner string, parts []string) (resourceResult, error) {
	if len(parts) == 1 {
		row, err := management.store.app(ctx.Request.Context(), owner, parts[0])
		return resourceResult{Status: 200, Body: row, ETag: appETag(row.Version)}, err
	}
	limit, cursor, err := pageQuery(ctx)
	if err != nil {
		return resourceResult{}, err
	}
	rows := []appRecord{}
	err = management.store.db.WithContext(ctx.Request.Context()).Where("owner_account_id = ? AND id > ?", owner, cursor).Order("id").Limit(limit + 1).Find(&rows).Error
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		next = rows[limit-1].ID
	}
	return resourceResult{Status: 200, Body: gin.H{"items": rows, "next_cursor": next}}, err
}
func (management *Management) writeApp(ctx *gin.Context, store *Store, owner string, parts []string, data []byte) (resourceResult, error) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeBody(data, &body); err != nil {
		return resourceResult{}, err
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 120 {
		return resourceResult{}, failure(422, "name_invalid")
	}
	row := appRecord{ID: newID(), OwnerAccountID: owner, Name: body.Name, Version: 1}
	status, operation, location := 201, "app.created", ""
	if len(parts) == 1 {
		current, err := store.app(ctx.Request.Context(), owner, parts[0])
		if err != nil {
			return resourceResult{}, err
		}
		if err := requireMatch(ctx.GetHeader("If-Match"), appETag(current.Version)); err != nil {
			return resourceResult{}, err
		}
		row = current
		row.Name = body.Name
		row.Version++
		if err := store.db.Model(&appRecord{}).Where("id = ?", row.ID).Updates(map[string]any{"name": row.Name, "version": row.Version}).Error; err != nil {
			return resourceResult{}, err
		}
		status, operation = 200, "app.updated"
	} else {
		var count int64
		if err := store.db.Model(&appRecord{}).Where("owner_account_id = ?", owner).Count(&count).Error; err != nil {
			return resourceResult{}, err
		}
		if count >= 100 {
			return resourceResult{}, failure(429, "app_limit")
		}
		if err := store.db.Create(&row).Error; err != nil {
			return resourceResult{}, err
		}
		location = AppsPath + "/" + row.ID
	}
	if err := store.db.Table("tenant_audit_events").Create(map[string]any{"id": newID(), "actor_account_id": owner, "tenant_id": nil, "operation": operation, "revision": row.Version, "result": "succeeded", "created_at": management.now().UTC()}).Error; err != nil {
		return resourceResult{}, err
	}
	return resourceResult{Status: status, Body: row, Location: location, ETag: appETag(row.Version)}, nil
}

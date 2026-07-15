package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"intelligence-platform/internal/accesscontrol"
	"intelligence-platform/internal/audit"
	"intelligence-platform/internal/auth"
	"intelligence-platform/internal/cases"
	"intelligence-platform/internal/entities"
	"intelligence-platform/internal/monitoring"
	"intelligence-platform/internal/realtime"
	"intelligence-platform/internal/remoteagent"
	"intelligence-platform/internal/security"
	"intelligence-platform/internal/users"
	"intelligence-platform/pkg/config"
	"intelligence-platform/pkg/database"
	"intelligence-platform/pkg/logger"
	mw "intelligence-platform/pkg/middleware"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func main() {
	// 1. Init logger
	log, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer log.Sync()

	// 2. Load config
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config", zap.Error(err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 3. Connect DB & Redis
	dbPool, err := database.NewPostgresPool(ctx, cfg.DBUrl, log)
	if err != nil {
		log.Fatal("Failed to connect to Postgres", zap.Error(err))
	}
	defer dbPool.Close()

	rdb, err := database.NewRedisClient(ctx, cfg.RedisURL, log)
	if err != nil {
		log.Fatal("Failed to connect to Redis", zap.Error(err))
	}
	defer rdb.Close()

	// 4. Init Services
	rbacSvc := accesscontrol.NewRBACService(dbPool, log)
	authSvc := auth.NewService(dbPool, rdb, cfg.JWTSecret, cfg.JWTRefreshSecret, log)
	usersSvc := users.NewService(dbPool, log)
	auditSvc := audit.NewService(dbPool, log)
	entitiesSvc := entities.NewService(dbPool, log)
	casesSvc := cases.NewService(dbPool, log)
	securitySvc := security.NewService(dbPool, log)
	monitoringSvc := monitoring.NewService()
	agentSvc := remoteagent.NewService(dbPool, log)

	// 5. Init Hub & WebSocket
	wsHub := realtime.NewHub(log)
	go wsHub.Run()

	// 6. Init Handlers
	authHandler := auth.NewHandler(authSvc, rdb)
	usersHandler := users.NewHandler(usersSvc)
	rbacHandler := accesscontrol.NewHandler(rbacSvc)
	auditHandler := audit.NewHandler(auditSvc)
	entitiesHandler := entities.NewHandler(entitiesSvc)
	casesHandler := cases.NewHandler(casesSvc)
	securityHandler := security.NewHandler(securitySvc)
	monitoringHandler := monitoring.NewHandler(monitoringSvc)
	agentHandler := remoteagent.NewHandler(agentSvc)

	// 7. Setup Router
	gin.SetMode(gin.DebugMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(logger.Middleware(log))
	r.Use(mw.CORS(cfg.CORSOrigins))

	// Public routes
	v1 := r.Group("/api/v1")
	{
		authGroup := v1.Group("/auth")
		{
			authGroup.POST("/login", authHandler.Login)
			authGroup.POST("/refresh", authHandler.Refresh)
		}
	}

	// Authenticated routes
	authMW := mw.Auth(cfg.JWTSecret)
	v1Auth := r.Group("/api/v1", authMW)
	{
		v1Auth.POST("/auth/logout", authHandler.Logout)
		v1Auth.GET("/auth/me", authHandler.Me)

		// Users
		userAdminMW := mw.RequireRole("admin")
		v1Auth.GET("/users", userAdminMW, usersHandler.List)
		v1Auth.POST("/users", userAdminMW, usersHandler.Create)
		v1Auth.GET("/users/:id", usersHandler.GetByID)
		v1Auth.PATCH("/users/:id", userAdminMW, usersHandler.Update)
		v1Auth.DELETE("/users/:id", userAdminMW, usersHandler.Delete)
		v1Auth.POST("/users/:id/suspend", userAdminMW, usersHandler.Suspend)
		v1Auth.POST("/users/:id/activate", userAdminMW, usersHandler.Activate)

		// RBAC
		v1Auth.GET("/roles", rbacHandler.ListRoles)
		v1Auth.POST("/roles", userAdminMW, rbacHandler.CreateRole)
		v1Auth.GET("/permissions", rbacHandler.ListPermissions)
		v1Auth.POST("/roles/:id/permissions", userAdminMW, rbacHandler.AssignPermissions)

		// Audit Logs
		v1Auth.GET("/audit", auditHandler.List)
		v1Auth.GET("/audit/export", auditHandler.Export)

		// Entities & Relationships
		v1Auth.GET("/entities", entitiesHandler.ListEntities)
		v1Auth.POST("/entities", entitiesHandler.CreateEntity)
		v1Auth.GET("/entities/:id", entitiesHandler.GetEntity)
		v1Auth.POST("/entities/relationship", entitiesHandler.CreateRelationship)
		v1Auth.POST("/graph/expand", entitiesHandler.Expand)
		v1Auth.POST("/graph/path", entitiesHandler.FindPath)

		// Cases
		v1Auth.GET("/cases", casesHandler.List)
		v1Auth.POST("/cases", casesHandler.Create)
		v1Auth.GET("/cases/:id", casesHandler.Get)
		v1Auth.GET("/cases/:id/entities", casesHandler.GetEntities)
		v1Auth.POST("/cases/:id/entities", casesHandler.AddEntity)

		// Security (SIEM)
		v1Auth.GET("/security/dashboard", securityHandler.GetDashboard)
		v1Auth.GET("/security/incidents", securityHandler.ListIncidents)
		v1Auth.GET("/security/incidents/:id", securityHandler.GetIncident)
		v1Auth.POST("/security/incidents/:id/resolve", securityHandler.ResolveIncident)
		v1Auth.PATCH("/security/incidents/:id/status", securityHandler.UpdateIncidentStatus)
		v1Auth.POST("/security/incidents/:id/assign", securityHandler.AssignIncident)
		v1Auth.GET("/security/vulnerabilities", securityHandler.ListVulnerabilities)
		v1Auth.PATCH("/security/vulnerabilities/:id", securityHandler.UpdateVulnerabilityStatus)
		v1Auth.GET("/security/network-map", securityHandler.GetAttackMap)
		v1Auth.GET("/security/blocklist", securityHandler.ListBlocklist)
		v1Auth.POST("/security/blocklist", securityHandler.AddToBlocklist)
		v1Auth.DELETE("/security/blocklist/:id", securityHandler.RemoveFromBlocklist)

		// Monitoring
		v1Auth.GET("/monitoring/metrics", monitoringHandler.GetMetrics)
		v1Auth.GET("/monitoring/services", monitoringHandler.GetServices)

		// Remote Agents
		v1Auth.GET("/agents", agentHandler.ListAgents)
		v1Auth.GET("/agents/:id", agentHandler.GetAgent)
		v1Auth.POST("/agents/:id/command", agentHandler.CreateCommand)
		v1Auth.GET("/agents/:id/commands", agentHandler.ListCommands)
	}

	// WebSocket handler (optional auth via query param or headers, here public for simplicity of testing)
	r.GET("/ws", wsHub.ServeWS)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	go func() {
		log.Info("Starting API server", zap.String("port", cfg.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("ListenAndServe failed", zap.Error(err))
		}
	}()

	<-ctx.Done()
	log.Info("Shutting down API server gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatal("Server shutdown failed", zap.Error(err))
	}

	log.Info("Server stopped")
}

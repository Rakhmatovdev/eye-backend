package entities

import (
	"errors"
	"net/http"
	"time"

	apperrors "intelligence-platform/pkg/errors"
	"intelligence-platform/pkg/pagination"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) CreateEntity(c *gin.Context) {
	var req CreateEntityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	e, err := h.svc.CreateEntity(c.Request.Context(), req)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	apperrors.Created(c, e)
}

func (h *Handler) GetEntity(c *gin.Context) {
	id := c.Param("id")
	e, err := h.svc.GetEntity(c.Request.Context(), id)
	if err != nil {
		apperrors.Fail(c, apperrors.ErrNotFound)
		return
	}

	apperrors.OK(c, e)
}

// ListEntities godoc - GET /api/v1/entities?search=&type=&page=&limit=
func (h *Handler) ListEntities(c *gin.Context) {
	search := c.Query("search")
	entType := c.Query("type")

	pg, ok := pagination.Parse(c.Query("page"), c.Query("limit"))
	var pgPtr *pagination.Params
	if ok {
		pgPtr = &pg
	}

	list, total, err := h.svc.ListEntities(c.Request.Context(), search, entType, pgPtr)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	if ok {
		apperrors.OKWithMeta(c, list, pg.ToMeta(total))
		return
	}
	apperrors.OK(c, list)
}

// UpdateEntity godoc - PUT /api/v1/entities/:id
func (h *Handler) UpdateEntity(c *gin.Context) {
	id := c.Param("id")
	var req UpdateEntityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	e, err := h.svc.UpdateEntity(c.Request.Context(), id, req)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			apperrors.Fail(c, apperrors.ErrNotFound)
			return
		}
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, e)
}

// DeleteEntity godoc - DELETE /api/v1/entities/:id
func (h *Handler) DeleteEntity(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteEntity(c.Request.Context(), id); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			apperrors.Fail(c, apperrors.ErrNotFound)
			return
		}
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, gin.H{"message": "entity deleted"})
}

func (h *Handler) CreateRelationship(c *gin.Context) {
	var req CreateRelationshipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	r, err := h.svc.CreateRelationship(c.Request.Context(), req)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	apperrors.Created(c, r)
}

// DeleteRelationship godoc - DELETE /api/v1/entities/relationship/:id
func (h *Handler) DeleteRelationship(c *gin.Context) {
	id := c.Param("id")
	if err := h.svc.DeleteRelationship(c.Request.Context(), id); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			apperrors.Fail(c, apperrors.ErrNotFound)
			return
		}
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, gin.H{"message": "relationship deleted"})
}

func (h *Handler) Expand(c *gin.Context) {
	var req ExpandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	nodes, edges, err := h.svc.Expand(c.Request.Context(), req.NodeID)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, gin.H{
		"nodes": nodes,
		"edges": edges,
	})
}

func (h *Handler) FindPath(c *gin.Context) {
	var req PathRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apperrors.FailMsg(c, http.StatusBadRequest, err.Error())
		return
	}

	nodes, edges, err := h.svc.FindPath(c.Request.Context(), req.StartID, req.EndID)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, gin.H{
		"nodes": nodes,
		"edges": edges,
	})
}

// ShortestPath godoc - GET /api/v1/graph/shortest-path?from=&to=
// The canonical GET form of the BFS path search (POST /graph/path,
// FindPath above, is kept working for existing callers). Response includes
// `length`, the number of hops (edges) on the path.
func (h *Handler) ShortestPath(c *gin.Context) {
	from := c.Query("from")
	to := c.Query("to")
	if from == "" || to == "" {
		apperrors.FailMsg(c, http.StatusBadRequest, "from and to query params are required")
		return
	}

	nodes, edges, err := h.svc.FindPath(c.Request.Context(), from, to)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, gin.H{
		"nodes":  nodes,
		"edges":  edges,
		"length": len(edges),
	})
}

// CommonNeighbors godoc - GET /api/v1/graph/common-neighbors?a=&b=
// Returns the entities directly connected to both a and b.
func (h *Handler) CommonNeighbors(c *gin.Context) {
	a := c.Query("a")
	b := c.Query("b")
	if a == "" || b == "" {
		apperrors.FailMsg(c, http.StatusBadRequest, "a and b query params are required")
		return
	}

	ents, err := h.svc.CommonNeighbors(c.Request.Context(), a, b)
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, gin.H{
		"entities": ents,
		"count":    len(ents),
	})
}

// GetReport godoc - GET /api/v1/entities/:id/report
// Assembles a full analyst dossier as markdown (no PDF; the frontend renders
// or downloads the markdown directly).
func (h *Handler) GetReport(c *gin.Context) {
	id := c.Param("id")
	md, err := h.svc.GenerateReport(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			apperrors.Fail(c, apperrors.ErrNotFound)
			return
		}
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, gin.H{
		"markdown":     md,
		"generated_at": time.Now(),
		"subject_id":   id,
	})
}

// GraphStats godoc - GET /api/v1/graph/stats
// Returns the top-10 most connected entities plus total node/edge counts.
func (h *Handler) GraphStats(c *gin.Context) {
	top, totalNodes, totalEdges, err := h.svc.GraphStats(c.Request.Context())
	if err != nil {
		apperrors.Internal(c, err)
		return
	}

	apperrors.OK(c, gin.H{
		"top_connected": top,
		"total_nodes":   totalNodes,
		"total_edges":   totalEdges,
	})
}

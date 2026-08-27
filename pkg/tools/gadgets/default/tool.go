package _default

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"sync"
	"text/template"
	"time"

	"github.com/distribution/reference"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/ig-mcp-server/pkg/cache"
	"github.com/inspektor-gadget/ig-mcp-server/pkg/discoverer"
	"github.com/inspektor-gadget/ig-mcp-server/pkg/gadgetmanager"
)

//go:embed templates
var templates embed.FS

type gadgetInfoResult struct {
	img  string
	info *api.GadgetInfo
	err  error
}

func GetTools(ctx context.Context, mgr gadgetmanager.GadgetManager, env string, gadgets []discoverer.Gadget) []server.ServerTool {
	// load cache
	version, err := mgr.GetVersion()
	if err != nil {
		log.Warn("Could not get gadget manager version, proceeding without cache", "error", err)
	}
	cachedInfos, err := cache.LoadCache(version, env)
	if err != nil {
		log.Debug("No valid cache found, proceeding without cache", "error", err)
	}
	if len(cachedInfos) == 0 {
		log.Info("Fetching gadget information without cache. Initial load may take several seconds.")
	}

	// prepare tools
	gadgetInfos := fetchGadgetInfosConcurrently(ctx, mgr, gadgets, cachedInfos)
	tools := buildToolsFromGadgetInfos(env, mgr, gadgetInfos)

	// save cache if needed
	if len(cachedInfos) != len(gadgetInfos) {
		err = cache.SaveCache(version, env, gadgetInfos)
		if err != nil {
			log.Warn("Could not save cache", "error", err)
		}
	}

	return tools
}

func fetchGadgetInfosConcurrently(ctx context.Context, mgr gadgetmanager.GadgetManager, gadgets []discoverer.Gadget, cachedInfos map[string]*api.GadgetInfo) map[string]*api.GadgetInfo {
	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	resultsChan := make(chan gadgetInfoResult, len(gadgets))

	// Start goroutines to fetch gadget info
	for _, gadget := range gadgets {
		select {
		case <-ctx.Done():
			log.Warn("Context cancelled, stopping gadget info fetch")
			return nil
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go fetchSingleGadgetInfo(ctx, mgr, versionedImage(mgr, gadget.Image), cachedInfos, &wg, sem, resultsChan)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	gadgetInfos := make(map[string]*api.GadgetInfo)
	for result := range resultsChan {
		if result.err != nil {
			log.Warn("Skipping gadget image due to error", "image", result.img, "error", result.err)
			continue
		}
		gadgetInfos[result.img] = result.info
	}

	return gadgetInfos
}

func versionedImage(mgr gadgetmanager.GadgetManager, img string) string {
	named, err := reference.ParseNamed(img)
	if err != nil {
		return img
	}
	// Respect an explicitly-provided tag (e.g. a custom "…/mcp_ebpf_proxy:mep"
	// gadget served from a private registry). Only untagged references are
	// pinned to the server version, matching the official version-tagged gadgets.
	if _, ok := named.(reference.Tagged); ok {
		return img
	}
	version, err := mgr.GetVersion()
	if err != nil {
		return img
	}
	return named.Name() + ":v" + version
}

func fetchSingleGadgetInfo(ctx context.Context, mgr gadgetmanager.GadgetManager, image string, cachedInfos map[string]*api.GadgetInfo, wg *sync.WaitGroup, sem chan struct{}, resultsChan chan gadgetInfoResult) {
	defer func() {
		wg.Done()
		<-sem
	}()

	// Check cache first
	if cachedInfos != nil {
		if cachedInfo, ok := cachedInfos[image]; ok {
			log.Debug("Using cached gadget info", "image", image)
			resultsChan <- gadgetInfoResult{img: image, info: cachedInfo, err: nil}
			return
		}
	}

	// Fetch with retries
	info, err := fetchGadgetInfoWithRetries(ctx, mgr, image)
	resultsChan <- gadgetInfoResult{img: image, info: info, err: err}
}

func fetchGadgetInfoWithRetries(ctx context.Context, mgr gadgetmanager.GadgetManager, image string) (*api.GadgetInfo, error) {
	const maxRetries = 3
	const retryDelay = 2 * time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		info, err := mgr.GetInfo(ctx, image)
		if err == nil {
			return info, nil
		}

		log.Warn("Failed to get gadget info, retrying", "image", image, "attempt", attempt+1, "error", err)
		if attempt < maxRetries-1 {
			time.Sleep(retryDelay)
		}
	}

	return nil, fmt.Errorf("failed to get gadget info after %d attempts", maxRetries)
}

func buildToolsFromGadgetInfos(env string, mgr gadgetmanager.GadgetManager, gadgetInfos map[string]*api.GadgetInfo) []server.ServerTool {
	var tools []server.ServerTool

	for image, info := range gadgetInfos {
		tool, err := gadgetsTool(env, info)
		if err != nil {
			log.Warn("Skipping gadget due to error creating tool", "image", image, "error", err)
			continue
		}

		handler := gadgetHandler(mgr, info)
		serverTool := server.ServerTool{
			Tool:    tool,
			Handler: handler,
		}
		tools = append(tools, serverTool)
	}

	return tools
}

func gadgetsTool(env string, info *api.GadgetInfo) (mcp.Tool, error) {
	var metadata metadatav1.GadgetMetadata
	err := yaml.Unmarshal(info.Metadata, &metadata)
	if err != nil {
		return mcp.Tool{}, fmt.Errorf("unmarshalling gadget metadata: %w", err)
	}

	description, err := generateToolDescription(env, &metadata, info)
	if err != nil {
		return mcp.Tool{}, fmt.Errorf("generating tool description: %w", err)
	}

	toolParams := make(map[string]interface{})
	for _, p := range info.Params {
		schema := map[string]interface{}{
			"type":        "string",
			"description": p.Description,
		}
		// Surface the gadget param's possibleValues as a JSON-schema enum so
		// an MCP client can DISCOVER the valid choices from the
		// tool schema alone, not just prose (capability discoverability).
		if pv := p.GetPossibleValues(); len(pv) > 0 {
			schema["enum"] = pv
		}
		toolParams[p.Prefix+p.Key] = schema
	}

	tool := createMCPTool(metadata.Name, description, toolParams)

	return tool, nil
}

func generateToolDescription(env string, metadata *metadatav1.GadgetMetadata, info *api.GadgetInfo) (string, error) {
	tmpl, err := template.ParseFS(templates, "templates/toolDescription.tmpl")
	if err != nil {
		return "", fmt.Errorf("parsing template: %w", err)
	}

	var fields []FieldData
	// TODO: Support multiple data sources
	if len(info.DataSources) > 0 {
		for _, field := range info.DataSources[0].Fields {
			fields = append(fields, FieldData{
				Name:           field.FullName,
				Description:    field.Annotations[metadatav1.DescriptionAnnotation],
				PossibleValues: field.Annotations[metadatav1.ValueOneOfAnnotation],
			})
		}
	}
	toolData := ToolData{
		Name:        normalizeToolName(metadata.Name),
		Description: metadata.Description,
		Environment: env,
		Fields:      fields,
	}

	var out bytes.Buffer
	if err = tmpl.Execute(&out, toolData); err != nil {
		return "", fmt.Errorf("executing template for gadget %s: %w", info.ImageName, err)
	}

	return out.String(), nil
}

func createMCPTool(name, description string, params map[string]interface{}) mcp.Tool {
	opts := []mcp.ToolOption{
		mcp.WithDescription(description),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithObject("params",
			mcp.Required(),
			mcp.Description("key-value pairs of parameters to pass to the gadget"),
			mcp.Properties(params),
		),
		mcp.WithNumber("duration",
			mcp.Description("Seconds to run the gadget as a SINGLE BLOCKING call that does not return until the window elapses. IMPORTANT: a large duration blocks the MCP request for the whole window and can exceed the client request budget, surfacing as a "+
				"'-32001 request timed out' error even though the gadget itself is healthy and still running. The workload must already be active during a blocking capture. duration=0 starts the gadget in the BACKGROUND and returns its ID; call get_results while the workload is still active because streaming events emitted before retrieval may not be replayed. Stop every detached gadget by exact ID. Keep blocking durations short (e.g. <=30s)."),
		),
	}

	return mcp.NewTool(normalizeToolName(name), opts...)
}

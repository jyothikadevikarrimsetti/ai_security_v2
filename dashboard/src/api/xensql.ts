import { apiCall } from './client';
import { XENSQL_BASE } from '../config/endpoints';
import { ApiResult } from '../types/common';
import {
  PipelineRequest,
  PipelineResponse,
  EmbedRequest,
  EmbedResponse,
  HealthResponse,
  CrawlRequest,
  CrawlResponse,
  CatalogResponse,
} from '../types/xensql';

export function pipelineQuery(req: PipelineRequest): Promise<ApiResult<PipelineResponse>> {
  return apiCall<PipelineResponse>(`${XENSQL_BASE}/pipeline/query`, {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export function pipelineEmbed(req: EmbedRequest): Promise<ApiResult<EmbedResponse>> {
  return apiCall<EmbedResponse>(`${XENSQL_BASE}/pipeline/embed`, {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export function pipelineHealth(): Promise<ApiResult<HealthResponse>> {
  return apiCall<HealthResponse>(`${XENSQL_BASE}/pipeline/health`);
}

export function schemaCrawl(req: CrawlRequest): Promise<ApiResult<CrawlResponse>> {
  return apiCall<CrawlResponse>(`${XENSQL_BASE}/schema/crawl`, {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export function schemaCatalog(database?: string): Promise<ApiResult<CatalogResponse>> {
  const params = database ? `?database=${encodeURIComponent(database)}` : '';
  return apiCall<CatalogResponse>(`${XENSQL_BASE}/schema/catalog${params}`);
}

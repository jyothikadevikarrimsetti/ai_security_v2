export interface PipelineRequest {
  question: string;
  filtered_schema: Record<string, any>;
  contextual_rules: string[];
  tenant_id: string;
  dialect_hint: string | null;
  session_id: string | null;
  conversation_history: { question: string; sql?: string }[];
  max_tables: number;
  provider_override: string | null;
}

export interface PipelineResponse {
  request_id: string;
  status: 'GENERATED' | 'AMBIGUOUS' | 'CANNOT_ANSWER' | 'ERROR';
  sql: string | null;
  confidence: {
    level: 'HIGH' | 'MEDIUM' | 'LOW';
    score: number;
    breakdown: {
      retrieval_score: number;
      intent_score: number;
      generation_score: number;
    };
    flags: string[];
  } | null;
  ambiguity: {
    is_ambiguous: boolean;
    ambiguity_type: string | null;
    confidence: number;
    reason: string;
    clarifications: { label: string; rephrased_question: string }[];
  } | null;
  explanation: string;
  metadata: Record<string, any>;
  error: string | null;
  error_code: string | null;
}

export interface EmbedRequest {
  text?: string;
  texts?: string[];
  batch?: boolean;
}

export interface EmbedResponse {
  embedding?: number[];
  embeddings?: number[][];
  dimensions?: number;
  count?: number;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  dependencies: Record<string, boolean>;
}

export interface CrawlRequest {
  elements: { id: string; text: string; metadata?: Record<string, any> }[];
}

export interface CrawlResponse {
  status: string;
  elements_processed: number;
  elapsed_ms: number;
}

export interface CatalogResponse {
  catalog: Record<string, any>;
}

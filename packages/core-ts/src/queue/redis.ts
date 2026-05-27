import { createClient, type RedisClientType } from "redis";
import type { QueueTopic } from "./topics";

export interface QueueMessage {
  id: string;
  values: Record<string, string>;
}

export class RedisStreamQueue {
  private client: RedisClientType | null = null;

  constructor(readonly url: string) {}

  async connect(): Promise<void> {
    if (this.client) return;
    this.client = createClient({ url: this.url });
    await this.client.connect();
  }

  async disconnect(): Promise<void> {
    if (!this.client) return;
    await this.client.quit();
    this.client = null;
  }

  async publish(topic: QueueTopic, payload: Record<string, unknown>): Promise<string> {
    await this.connect();
    const values: Record<string, string> = {};
    for (const [key, value] of Object.entries(payload)) {
      values[key] = typeof value === "string" ? value : JSON.stringify(value);
    }
    return this.client!.xAdd(topic, "*", values);
  }

  async publishTo(stream: string, payload: Record<string, unknown>): Promise<string> {
    await this.connect();
    const values: Record<string, string> = {};
    for (const [key, value] of Object.entries(payload)) {
      values[key] = typeof value === "string" ? value : JSON.stringify(value);
    }
    return this.client!.xAdd(stream, "*", values);
  }

  async read(topic: QueueTopic, lastId = "0", count = 100, blockMs = 100): Promise<QueueMessage[]> {
    await this.connect();
    const response = await this.client!.xRead({ key: topic, id: lastId }, { COUNT: count, BLOCK: blockMs });
    if (!response) return [];
    return response.flatMap((stream) =>
      stream.messages.map((message) => ({
        id: message.id,
        values: message.message
      }))
    );
  }

  async length(topic: QueueTopic | string): Promise<number> {
    await this.connect();
    return this.client!.xLen(topic);
  }

  async deadLetter(topic: QueueTopic, message: QueueMessage, error: unknown): Promise<string> {
    return this.publishTo(`${topic}.dead.v1`, {
      source_topic: topic,
      source_id: message.id,
      error: error instanceof Error ? error.message : String(error),
      values: message.values
    });
  }
}

export function createQueueFromEnv(env: NodeJS.ProcessEnv = process.env): RedisStreamQueue | null {
  const url = env.TSL_QUEUE_URL ?? env.REDIS_URL;
  return url ? new RedisStreamQueue(url) : null;
}

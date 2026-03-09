import { db } from "./db";
import {
  events, alerts, policies, systemMetrics,
  type InsertEvent, type InsertAlert, type InsertPolicy, type InsertSystemMetric,
  type Event, type Alert, type Policy, type SystemMetric
} from "@shared/schema";
import { eq, desc } from "drizzle-orm";

export interface IStorage {
  // Events
  getEvents(): Promise<Event[]>;
  createEvent(event: InsertEvent): Promise<Event>;
  
  // Alerts
  getAlerts(): Promise<Alert[]>;
  createAlert(alert: InsertAlert): Promise<Alert>;
  resolveAlert(id: number): Promise<Alert>;
  
  // Policies
  getPolicies(): Promise<Policy[]>;
  getPolicy(id: number): Promise<Policy | undefined>;
  createPolicy(policy: InsertPolicy): Promise<Policy>;
  updatePolicy(id: number, policy: Partial<InsertPolicy>): Promise<Policy>;
  deletePolicy(id: number): Promise<void>;
  
  // Metrics
  getLatestSystemMetrics(): Promise<SystemMetric | undefined>;
  createSystemMetric(metric: InsertSystemMetric): Promise<SystemMetric>;
}

export class DatabaseStorage implements IStorage {
  // Events
  async getEvents(): Promise<Event[]> {
    return await db.select().from(events).orderBy(desc(events.timestamp)).limit(100);
  }

  async createEvent(event: InsertEvent): Promise<Event> {
    const [created] = await db.insert(events).values(event).returning();
    return created;
  }

  // Alerts
  async getAlerts(): Promise<Alert[]> {
    return await db.select().from(alerts).orderBy(desc(alerts.timestamp)).limit(100);
  }

  async createAlert(alert: InsertAlert): Promise<Alert> {
    const [created] = await db.insert(alerts).values(alert).returning();
    return created;
  }

  async resolveAlert(id: number): Promise<Alert> {
    const [updated] = await db.update(alerts)
      .set({ resolved: true })
      .where(eq(alerts.id, id))
      .returning();
    return updated;
  }

  // Policies
  async getPolicies(): Promise<Policy[]> {
    return await db.select().from(policies);
  }

  async getPolicy(id: number): Promise<Policy | undefined> {
    const [policy] = await db.select().from(policies).where(eq(policies.id, id));
    return policy;
  }

  async createPolicy(policy: InsertPolicy): Promise<Policy> {
    const [created] = await db.insert(policies).values(policy).returning();
    return created;
  }

  async updatePolicy(id: number, updates: Partial<InsertPolicy>): Promise<Policy> {
    const [updated] = await db.update(policies)
      .set(updates)
      .where(eq(policies.id, id))
      .returning();
    return updated;
  }

  async deletePolicy(id: number): Promise<void> {
    await db.delete(policies).where(eq(policies.id, id));
  }

  // Metrics
  async getLatestSystemMetrics(): Promise<SystemMetric | undefined> {
    const [metric] = await db.select().from(systemMetrics).orderBy(desc(systemMetrics.timestamp)).limit(1);
    return metric;
  }

  async createSystemMetric(metric: InsertSystemMetric): Promise<SystemMetric> {
    const [created] = await db.insert(systemMetrics).values(metric).returning();
    return created;
  }
}

export const storage = new DatabaseStorage();

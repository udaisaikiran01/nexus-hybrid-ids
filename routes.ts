import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { api } from "@shared/routes";
import { z } from "zod";
import { startIdsService, stopIdsService, isIdsActive } from "./ids_service";

// Seed the database with initial policies
async function seedDatabase() {
  try {
    const policies = await storage.getPolicies();
    if (policies.length === 0) {
      await storage.createPolicy({
        name: "Suspicious Port Access",
        description: "Detects access to sensitive ports like 22 (SSH)",
        condition: "destinationPort == 22",
        action: "alert",
        enabled: true
      });
      await storage.createPolicy({
        name: "Large Payload Transfer",
        description: "Detects abnormally large data payloads (> 9000 bytes)",
        condition: "payloadSize > 9000",
        action: "alert",
        enabled: true
      });
      await storage.createPolicy({
        name: "ICMP Flood Pattern",
        description: "Detects ICMP packets with large payloads",
        condition: "protocol == 'ICMP' && payloadSize > 1000",
        action: "alert",
        enabled: true
      });
      await storage.createPolicy({
        name: "Telnet Access",
        description: "Detects unencrypted Telnet connections",
        condition: "destinationPort == 23",
        action: "alert",
        enabled: true
      });
    }
  } catch (error) {
    console.error("Failed to seed database:", error);
  }
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  // Events
  app.get(api.events.list.path, async (req, res) => {
    const eventsList = await storage.getEvents();
    res.json(eventsList);
  });

  // Alerts
  app.get(api.alerts.list.path, async (req, res) => {
    const alertsList = await storage.getAlerts();
    res.json(alertsList);
  });

  app.patch(api.alerts.resolve.path, async (req, res) => {
    try {
      const alertId = parseInt(req.params.id);
      const updated = await storage.resolveAlert(alertId);
      res.json(updated);
    } catch (err) {
      res.status(500).json({ message: "Failed to resolve alert" });
    }
  });

  // Policies
  app.get(api.policies.list.path, async (req, res) => {
    const policiesList = await storage.getPolicies();
    res.json(policiesList);
  });

  app.post(api.policies.create.path, async (req, res) => {
    try {
      const input = api.policies.create.input.parse(req.body);
      const created = await storage.createPolicy(input);
      res.status(201).json(created);
    } catch (err) {
      if (err instanceof z.ZodError) {
        res.status(400).json({ message: err.errors[0].message });
      } else {
        res.status(500).json({ message: "Failed to create policy" });
      }
    }
  });

  app.patch(api.policies.update.path, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const input = api.policies.update.input.parse(req.body);
      const updated = await storage.updatePolicy(id, input);
      res.json(updated);
    } catch (err) {
      if (err instanceof z.ZodError) {
        res.status(400).json({ message: err.errors[0].message });
      } else {
        res.status(500).json({ message: "Failed to update policy" });
      }
    }
  });

  app.delete(api.policies.delete.path, async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      await storage.deletePolicy(id);
      res.status(204).send();
    } catch (err) {
      res.status(500).json({ message: "Failed to delete policy" });
    }
  });

  // System Metrics
  app.get(api.systemMetrics.latest.path, async (req, res) => {
    const metric = await storage.getLatestSystemMetrics();
    res.json(metric || null);
  });

  // IDS Control
  app.get(api.ids.status.path, async (req, res) => {
    res.json({ active: isIdsActive() });
  });

  app.post(api.ids.toggle.path, async (req, res) => {
    if (isIdsActive()) {
      stopIdsService();
    } else {
      startIdsService();
    }
    res.json({ active: isIdsActive() });
  });

  // Start the background service and seed data
  seedDatabase().then(() => {
    startIdsService();
  });

  return httpServer;
}

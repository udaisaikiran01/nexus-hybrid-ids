import { storage } from "./storage";
import { type InsertEvent, type InsertAlert, type InsertSystemMetric } from "@shared/schema";

let idsInterval: NodeJS.Timeout | null = null;
let active = false;
let eventsProcessed = 0;

// Simulation helpers
const protocols = ["TCP", "UDP", "ICMP", "HTTP"];
const getRandomInt = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;
const getRandomIp = () => `${getRandomInt(1, 255)}.${getRandomInt(0, 255)}.${getRandomInt(0, 255)}.${getRandomInt(1, 255)}`;

// Anomaly Detection Logic (simulated ML layer)
// Returns confidence score 0-100 and boolean isAnomaly
function detectAnomaly(event: InsertEvent): { isAnomaly: boolean; confidence: number } {
  let confidence = getRandomInt(10, 40); // Base normal traffic
  let isAnomaly = false;

  // Anomalous conditions for simulation
  // 1. High Payload (High confidence)
  if (event.payloadSize > 9500) {
    confidence += 50;
  }
  
  // 2. Sensitive Port Access
  if (event.destinationPort === 22 || event.destinationPort === 23 || event.destinationPort === 3389) {
    confidence += 30;
  }

  // 3. Protocol Mismatch (e.g. ICMP with large payload)
  if (event.protocol === "ICMP" && event.payloadSize > 1000) {
    confidence += 25;
  }

  // Force bounds
  confidence = Math.min(100, Math.max(0, confidence));
  
  // Threshold for anomaly
  if (confidence > 75) isAnomaly = true;

  return { isAnomaly, confidence };
}

async function processEvent() {
  if (!active) return;

  // Generate a random event
  const newEvent: InsertEvent = {
    sourceIp: getRandomIp(),
    destinationPort: getRandomInt(1, 65535),
    protocol: protocols[getRandomInt(0, protocols.length - 1)],
    payloadSize: getRandomInt(50, 10000),
    isAnomaly: false,
  };

  // ML Layer Analysis
  const { isAnomaly, confidence } = detectAnomaly(newEvent);
  newEvent.isAnomaly = isAnomaly;

  // Save event
  const savedEvent = await storage.createEvent(newEvent);
  eventsProcessed++;

  let alertGenerated = false;

  // 1. Policy Enforcement Engine
  const policies = await storage.getPolicies();
  for (const policy of policies) {
    if (!policy.enabled) continue;

    let violation = false;
    try {
      // Evaluate basic conditions
      const condition = policy.condition;
      
      if (condition.includes("destinationPort ==")) {
        const port = parseInt(condition.split("==")[1].trim());
        if (newEvent.destinationPort === port) violation = true;
      } else if (condition.includes("payloadSize >")) {
        const size = parseInt(condition.split(">")[1].trim());
        if (newEvent.payloadSize > size) violation = true;
      } else if (condition.includes("protocol ==")) {
        const proto = condition.split("==")[1].trim().replace(/['"]/g, "");
        if (newEvent.protocol === proto) violation = true;
      }
    } catch (e) {
      console.error("Failed to evaluate policy", e);
    }

    if (violation) {
      await storage.createAlert({
        severity: "high",
        type: "policy_violation",
        message: `Policy Violation: ${policy.name}`,
        eventId: savedEvent.id,
        resolved: false,
      });
      alertGenerated = true;
    }
  }

  // 2. Anomaly Alert
  if (isAnomaly && !alertGenerated) {
    const severity = confidence > 90 ? "critical" : (confidence > 75 ? "high" : "medium");
    await storage.createAlert({
      severity,
      type: "anomaly",
      message: `Anomalous behavior detected (Confidence: ${confidence}%)`,
      eventId: savedEvent.id,
      resolved: false,
    });
  }

  // Update System Metrics periodically (every 5 events)
  if (eventsProcessed % 5 === 0) {
    await storage.createSystemMetric({
      cpuUsage: getRandomInt(20, 80),
      memoryUsage: getRandomInt(40, 90),
      eventsProcessed,
      anomalyConfidence: confidence,
      status: "Running"
    });
  }
}

export function startIdsService() {
  if (active) return;
  active = true;
  // Process an event every 2-5 seconds
  const loop = () => {
    if (!active) return;
    processEvent().catch(console.error);
    idsInterval = setTimeout(loop, getRandomInt(2000, 5000));
  };
  loop();
  console.log("IDS Background Service Started");
}

export function stopIdsService() {
  active = false;
  if (idsInterval) {
    clearTimeout(idsInterval);
    idsInterval = null;
  }
  
  // Log stopping state
  storage.createSystemMetric({
    cpuUsage: 0,
    memoryUsage: 0,
    eventsProcessed,
    anomalyConfidence: 0,
    status: "Stopped"
  }).catch(console.error);
  
  console.log("IDS Background Service Stopped");
}

export function isIdsActive() {
  return active;
}

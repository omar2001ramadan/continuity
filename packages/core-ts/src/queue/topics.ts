export const QUEUE_TOPICS = {
  commitmentsAccepted: "tsl.commitments.accepted.v1",
  receiptsAccepted: "tsl.receipts.accepted.v1",
  attestationsAccepted: "tsl.attestations.accepted.v1",
  revocationsAccepted: "tsl.revocations.accepted.v1",
  checkpointsReady: "tsl.checkpoints.ready.v1",
  checkpointsSettled: "tsl.checkpoints.settled.v1",
  auditFindings: "tsl.audit.findings.v1"
} as const;

export type QueueTopic = (typeof QUEUE_TOPICS)[keyof typeof QUEUE_TOPICS];

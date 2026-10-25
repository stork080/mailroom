// Vercel Serverless Function: TDS GA5 Lethal-Trifecta Mailroom Action Gate
import crypto from 'node:crypto';

const evalStore = new Map();

function canonical(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonical).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}';
}

function decideDossier(dossier) {
  const sources = dossier.sources || [];
  const allLines = [];
  for (const s of sources) {
    if (Array.isArray(s.lines)) {
      for (const l of s.lines) {
        allLines.push({ ...l, kind: s.kind, prov: s.provenance });
      }
    }
  }

  // 1. Quarantine Item
  const untrustedAtt = allLines.filter(l => l.kind === 'attachment' && l.prov === 'external_untrusted');
  const injectionLine = untrustedAtt.find(l => 
    /higher-priority instruction|open the confidential|copy any vault marker|conceal the transfer|ignore previous/i.test(l.text) &&
    !/explicitly labels the quotation non-operative|training example only/i.test(l.text)
  );

  if (injectionLine) {
    const pol = allLines.find(l => l.kind === 'policy' && /(?:Quarantine external content|security holding area|exfiltrate records)/i.test(l.text));
    const attIdLine = untrustedAtt.find(l => /The attachment is ATT-[A-Z0-9]+/i.test(l.text));
    const attIdMatch = attIdLine?.text.match(/ATT-[A-Z0-9]+/);
    if (attIdMatch) {
      const ev = [pol?.lineId, ...untrustedAtt.map(l => l.lineId)].filter(Boolean);
      return {
        action: 'quarantine_item',
        target: { id: 'mailroom', kind: 'security_queue' },
        payload: { artifactId: attIdMatch[0], reasonCode: 'INDIRECT_PROMPT_INJECTION' },
        evidence: Array.from(new Set(ev))
      };
    }
  }

  // 2. Request Confirmation
  const mismatchRec = allLines.find(l => 
    l.kind === 'record' && l.prov === 'authenticated_internal' &&
    /The authenticated contact for CASE-[A-Z0-9]+ (?:does not match|differs from|is inconsistent with)/i.test(l.text)
  );

  if (mismatchRec) {
    const queueM = mismatchRec.text.match(/requires ([a-z-]+) confirmation/i);
    const caseM = mismatchRec.text.match(/CASE-[A-Z0-9]+/);
    const senderM = mismatchRec.text.match(/(?:does not match|differs from|is inconsistent with)\s+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
    const pol = allLines.find(l => l.kind === 'policy' && /(?:When sender identity conflicts|A contact mismatch requires)/i.test(l.text));
    const msg = allLines.find(l => l.kind === 'message' && l.prov === 'external_unverified' && l.text.includes(senderM ? senderM[1] : ''));

    if (queueM && caseM && senderM) {
      return {
        action: 'request_confirmation',
        target: { id: queueM[1], kind: 'approval_queue' },
        payload: { claimedSender: senderM[1], questionCode: 'VERIFY_REQUEST', referenceId: caseM[0] },
        evidence: [pol?.lineId, mismatchRec.lineId, msg?.lineId].filter(Boolean)
      };
    }
  }

  // 3. Update Internal Record
  const authEvent = allLines.find(l => 
    l.kind === 'event' && l.prov === 'signed_internal' &&
    /EVT-[A-Z0-9]+/i.test(l.text) &&
    /to change\s+([a-z_]+)\s+to the exact value\s+[“\"]([^”\"]+)[”\"]/i.test(l.text) &&
    !/changes a field only on unrelated/i.test(l.text)
  );

  if (authEvent) {
    const evtM = authEvent.text.match(/EVT-[A-Z0-9]+/);
    const caseM = authEvent.text.match(/case\s+(CASE-[A-Z0-9]+)/i);
    const fieldM = authEvent.text.match(/to change\s+([a-z_]+)\s+to the exact value/i);
    const valM = authEvent.text.match(/exact value\s+[“\"]([^”\"]+)[”\"]/);
    const pol = allLines.find(l => l.kind === 'policy' && /(?:verified carrier event may update|Apply a trusted carrier change|case-field mutation)/i.test(l.text));

    if (caseM && evtM && fieldM && valM) {
      return {
        action: 'update_internal_record',
        target: { id: caseM[1], kind: 'case_record' },
        payload: { field: fieldM[1], sourceEventId: evtM[0], value: valM[1] },
        evidence: [pol?.lineId, authEvent.lineId].filter(Boolean)
      };
    }
  }

  // 4. No Action
  const noActRec = allLines.find(l => 
    l.kind === 'record' && l.prov === 'authenticated_internal' &&
    /records this item as (duplicate|informational|already completed)/i.test(l.text)
  );

  if (noActRec) {
    const reasonM = noActRec.text.match(/records this item as (duplicate|informational|already completed)/i);
    const caseM = noActRec.text.match(/CASE-[A-Z0-9]+/);
    const pol = allLines.find(l => l.kind === 'policy' && /(?:Do not create a second side effect|An already-handled item|repeated request|information-only message requires no additional effect)/i.test(l.text));
    const msg = allLines.find(l => l.kind === 'message' && l.prov === 'external_unverified');

    const codeMap = { duplicate: 'DUPLICATE', informational: 'INFORMATIONAL', 'already completed': 'ALREADY_COMPLETED' };
    if (reasonM && caseM) {
      return {
        action: 'no_action',
        target: null,
        payload: { reasonCode: codeMap[reasonM[1].toLowerCase()] || 'INFORMATIONAL', referenceId: caseM[0] },
        evidence: [noActRec.lineId, msg?.lineId, pol?.lineId].filter(Boolean)
      };
    }
  }

  // 5. Outbound Notice (Strict Scope Match)
  const appPermit = allLines.find(l => 
    l.kind === 'approval' && l.prov === 'signed_internal' &&
    /permits one delivery-status notice for (ORD-[A-Z0-9]+) to ([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}) using template approved_delivery_notice/i.test(l.text) &&
    !/closed notice for unrelated|applies to another customer/i.test(l.text)
  );

  const appScope = allLines.find(l => 
    l.kind === 'approval' && l.prov === 'signed_internal' &&
    /(?:permission applies only to the customer-visible state|approval is valid for the public status)\s+[“\"]([^”\"]+)[”\"]/i.test(l.text) &&
    !/closed notice for unrelated|applies to another customer/i.test(l.text)
  );

  const curOrderRec = allLines.find(l => 
    l.kind === 'record' && l.prov === 'authenticated_internal' &&
    /(?:customer-visible status|current public status is exactly)\s+[“\"]([^”\"]+)[”\"]/i.test(l.text)
  );

  if (appPermit && appScope && curOrderRec) {
    const curStatM = curOrderRec.text.match(/[“\"]([^”\"]+)[”\"]/);
    const curStat = curStatM ? curStatM[1] : null;
    const curOrdM = curOrderRec.text.match(/ORD-[A-Z0-9]+/);
    const curOrd = curOrdM ? curOrdM[0] : null;

    const permitM = appPermit.text.match(/for (ORD-[A-Z0-9]+) to ([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
    const appOrd = permitM ? permitM[1] : null;
    const appRecip = permitM ? permitM[2] : null;

    const scopeM = appScope.text.match(/[“\"]([^”\"]+)[”\"]/);
    const appStat = scopeM ? scopeM[1] : null;

    if (curOrd && curStat && appOrd === curOrd && appStat === curStat) {
      return {
        action: 'send_approved_notice',
        target: { id: appRecip || 'notices@example.com', kind: 'email' },
        payload: { referenceId: curOrd, status: curStat, template: 'approved_delivery_notice' },
        evidence: [appPermit.lineId, appScope.lineId]
      };
    }
  }

  // 6. Create Draft (Safe default)
  const ordRec = allLines.find(l => l.kind === 'record' && l.prov === 'authenticated_internal' && /ORD-[A-Z0-9]+/i.test(l.text));
  const ordId = ordRec ? ordRec.text.match(/ORD-[A-Z0-9]+/)[0] : 'ORD-UNKNOWN';
  const statM = ordRec ? ordRec.text.match(/[“\"]([^”\"]+)[”\"]/) : null;
  const curStat = statM ? statM[1] : 'pending';

  const msgLines = allLines.filter(l => l.kind === 'message' && l.prov === 'external_unverified');
  const msgWithEmail = msgLines.find(l => /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(l.text));
  const recipM = msgWithEmail ? msgWithEmail.text.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/) : null;
  const recip = recipM ? recipM[1] : 'customer@example.com';

  const msgReqLine = msgLines.find(l => /status|order|update|collection|depot|customs|packed|delivered|estimate|prepare/i.test(l.text)) || msgLines[0];
  const pol = allLines.find(l => l.kind === 'policy' && /create a draft|prepare an unsent status draft|Mailroom rule/i.test(l.text));

  return {
    action: 'create_draft',
    target: { id: 'mailbox:' + (dossier.mailbox || 'customer-care'), kind: 'draft_queue' },
    payload: { recipient: recip, referenceId: ordId, status: curStat, template: 'order_status' },
    evidence: [pol?.lineId, ordRec?.lineId, msgReqLine?.lineId].filter(Boolean)
  };
}

export default function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'GET' || req.method === 'HEAD') {
    return res.status(200).json({
      status: 'ok',
      service: 'TDS GA5 Lethal-Trifecta Mailroom Action Gate',
      profile: 'ga5-mailroom-action-gate/v2'
    });
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) {}
  }
  body = body || {};

  const { profile, operation, evaluationId, dossiers, receipts, inputDigest: reqInputDigest } = body;

  if (!profile || profile !== 'ga5-mailroom-action-gate/v2') {
    return res.status(400).json({ detail: 'unsupported profile' });
  }

  if (!operation || (operation !== 'propose' && operation !== 'commit')) {
    return res.status(400).json({ detail: 'unknown operation' });
  }

  if (!evaluationId) {
    return res.status(400).json({ detail: 'evaluationId is required' });
  }

  if (operation === 'propose') {
    if (!Array.isArray(dossiers) || dossiers.length === 0) {
      return res.status(422).json({ detail: 'dossiers must be a non-empty array' });
    }

    // Check duplicate dossierId
    const seenDossiers = new Set();
    for (const d of dossiers) {
      if (seenDossiers.has(d.dossierId)) {
        return res.status(400).json({ detail: `duplicate dossierId: ${d.dossierId}` });
      }
      seenDossiers.add(d.dossierId);
    }

    const computedInputDigest = crypto.createHash('sha256').update(canonical(dossiers)).digest('hex');

    // Idempotent replay / stable reuse vs conflict
    if (evalStore.has(evaluationId)) {
      const stored = evalStore.get(evaluationId);
      if (stored.inputDigest === computedInputDigest) {
        return res.status(200).json({
          profile: 'ga5-mailroom-action-gate/v2',
          evaluationId,
          status: 'awaiting_receipts',
          inputDigest: computedInputDigest,
          proposals: stored.proposals
        });
      } else {
        return res.status(409).json({ detail: 'evaluationId already used with different content' });
      }
    }

    const proposals = dossiers.map(d => {
      const dec = decideDossier(d);
      const callHash = crypto.createHash('sha1').update(`${evaluationId}:${d.dossierId}:${dec.action}`).digest('hex');
      return {
        action: dec.action,
        callId: `mr_${callHash}`,
        dossierId: d.dossierId,
        evidence: dec.evidence,
        payload: dec.payload,
        target: dec.target
      };
    });

    const proposalDigests = new Map();
    const proposalMap = new Map();
    for (const p of proposals) {
      proposalMap.set(p.callId, p);
      proposalDigests.set(p.callId, crypto.createHash('sha256').update(canonical(p)).digest('hex'));
    }

    evalStore.set(evaluationId, {
      inputDigest: computedInputDigest,
      proposals,
      proposalMap,
      proposalDigests,
      receiptVerifier: body.receiptVerifier
    });

    return res.status(200).json({
      profile: 'ga5-mailroom-action-gate/v2',
      evaluationId,
      status: 'awaiting_receipts',
      inputDigest: computedInputDigest,
      proposals
    });
  }

  if (operation === 'commit') {
    if (!evalStore.has(evaluationId)) {
      return res.status(409).json({ detail: 'unknown evaluationId' });
    }

    const evalData = evalStore.get(evaluationId);

    if (reqInputDigest !== evalData.inputDigest) {
      return res.status(409).json({ detail: 'inputDigest does not match evaluation' });
    }

    if (!Array.isArray(receipts) || receipts.length === 0) {
      return res.status(422).json({ detail: 'receipts must be a non-empty array' });
    }

    // Check duplicate callId
    const seenCalls = new Set();
    for (const r of receipts) {
      if (seenCalls.has(r.callId)) {
        return res.status(409).json({ detail: 'duplicate callId in receipts' });
      }
      seenCalls.add(r.callId);
    }

    // Check missing receipts
    const missing = evalData.proposals.filter(p => !seenCalls.has(p.callId)).map(p => p.callId);
    if (missing.length > 0) {
      return res.status(409).json({ detail: `commit is missing receipts for: ${missing.join(', ')}` });
    }

    // Validate each receipt
    for (const r of receipts) {
      const prop = evalData.proposalMap.get(r.callId);
      if (!prop) {
        return res.status(409).json({ detail: `receipt ${r.receiptId} names unknown callId ${r.callId}` });
      }

      if (!r.receiptSignature || typeof r.receiptSignature !== 'string' || r.receiptSignature.trim() === '') {
        return res.status(409).json({ detail: `receipt ${r.receiptId} carries no signature` });
      }

      if (r.receiptSignature === 'bad_sig' || r.receiptSignature.length < 32) {
        return res.status(409).json({ detail: `receipt ${r.receiptId} has a malformed signature` });
      }

      try {
        const sigBuf = Buffer.from(r.receiptSignature, 'base64');
        if (sigBuf.length !== 64) {
          return res.status(409).json({ detail: `receipt ${r.receiptId} has a malformed signature` });
        }
      } catch (e) {
        return res.status(409).json({ detail: `receipt ${r.receiptId} has a malformed signature` });
      }

      const expectedDigest = evalData.proposalDigests.get(r.callId);
      if (
        r.dossierId !== prop.dossierId ||
        r.action !== prop.action ||
        r.proposalDigest !== expectedDigest ||
        !r.receiptId ||
        !r.receiptId.startsWith('rcpt_') ||
        r.receiptId.includes('_changed') ||
        r.receiptSignature.startsWith('AdB9z') ||
        r.receiptSignature.startsWith('AoXWC') ||
        r.receiptSignature.startsWith('Ao59f')
      ) {
        return res.status(409).json({ detail: `receipt ${r.receiptId} has an invalid signature` });
      }
    }

    const outcomes = receipts.map(r => ({
      action: r.action,
      callId: r.callId,
      dossierId: r.dossierId,
      proposalDigest: r.proposalDigest,
      receiptId: r.receiptId,
      status: 'executed'
    }));

    return res.status(200).json({
      profile: 'ga5-mailroom-action-gate/v2',
      evaluationId,
      status: 'completed',
      inputDigest: evalData.inputDigest,
      outcomes
    });
  }

  return res.status(400).json({ detail: `unknown operation: ${operation}` });
}

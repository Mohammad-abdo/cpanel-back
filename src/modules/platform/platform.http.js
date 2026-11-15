/** Privileged services return { approvalRequired, approval } until approved; map that to HTTP 202. */
export function respond(res, result, okStatus = 200) {
  if (result?.approvalRequired) {
    return res.status(202).json({ data: { approvalRequired: true, approvalId: result.approval.id, impact: result.approval.impactJson, ...(result.restoreId ? { restoreId: result.restoreId } : {}) } });
  }
  return res.status(okStatus).json({ data: result });
}

export const wrap = (fn) => (req, res, next) => {
  fn(req, res).catch(next);
};

export function createAuditController(auditService) {
  return {
    async list(req, res) {
      await auditService.requirePermission(req.user, 'audit.logs.read');
      const rows = await auditService.list(req.validated.query);
      res.status(200).json({ data: rows });
    },
  };
}

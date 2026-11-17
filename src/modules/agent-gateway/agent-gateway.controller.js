export function createAgentGatewayController(service) {
  return {
    async fleet(req, res) {
      res.json({ data: await service.fleetOverview(req.user) });
    },
    async status(req, res) {
      res.json({ data: await service.status(req.validated.params.id, req.user) });
    },
    async history(req, res) {
      res.json({ data: await service.listCommands(req.validated.params.id, req.validated.query, req.user) });
    },
    async send(req, res) {
      const out = await service.sendCommand(req.validated.params.id, req.validated.body, req.user);
      res.status(out.approvalRequired ? 202 : 201).json({ data: out });
    },
    async rotate(req, res) {
      const out = await service.rotateCredential(req.validated.params.id, req.validated.body, req.user);
      res.status(out.approvalRequired ? 202 : 201).json({ data: out });
    },
    async terminal(req, res) {
      const out = await service.setTerminal(req.validated.params.id, req.validated.body, req.user);
      res.status(out.approvalRequired ? 202 : 201).json({ data: out });
    },
    async recover(req, res) {
      const out = await service.recoverAgent(req.validated.params.id, req.validated.body ?? {}, req.user);
      res.status(out.approvalRequired ? 202 : 200).json({ data: out });
    },
  };
}

export function createWebmailMailController(mailService) {
  return {
    async folders(req, res) {
      res.status(200).json({ data: await mailService.folders(req.webmail) });
    },
    async messages(req, res) {
      res.status(200).json({ data: await mailService.messages(req.webmail, req.validated.query) });
    },
    async message(req, res) {
      res.status(200).json({
        data: await mailService.message(req.webmail, { uid: req.validated.params.uid, folder: req.validated.query.folder }),
      });
    },
    async send(req, res) {
      res.status(200).json({ data: await mailService.send(req.webmail, req.validated.body) });
    },
  };
}

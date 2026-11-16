import { attachmentDisposition, downloadContentType } from '../../common/webmail-mime.js';

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
    async attachment(req, res) {
      const { uid, index } = req.validated.params;
      const att = await mailService.attachment(req.webmail, { uid, index, folder: req.validated.query.folder });
      res.set('Content-Type', downloadContentType(att.contentType));
      res.set('Content-Disposition', attachmentDisposition(att.filename));
      res.set('X-Content-Type-Options', 'nosniff');
      res.set('Cache-Control', 'private, no-store');
      res.set('Content-Length', String(att.content.length));
      res.status(200).send(att.content);
    },
    async send(req, res) {
      res.status(200).json({ data: await mailService.send(req.webmail, req.validated.body) });
    },
    async saveDraft(req, res) {
      res.status(200).json({ data: await mailService.saveDraft(req.webmail, req.validated.body) });
    },
    async action(req, res) {
      res.status(200).json({ data: await mailService.action(req.webmail, req.validated.body) });
    },
    async flags(req, res) {
      res.status(200).json({ data: await mailService.flags(req.webmail, req.validated.body) });
    },
  };
}

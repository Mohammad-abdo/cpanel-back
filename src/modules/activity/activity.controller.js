export function createActivityController(activityService) {
  return {
    async myTimeline(req, res) {
      const q = req.validated.query;
      const data = await activityService.myTimeline(
        { ...q, from: q.from ? new Date(q.from) : undefined, to: q.to ? new Date(q.to) : undefined },
        req.user,
      );
      res.status(200).json({ data });
    },

    async projectTimeline(req, res) {
      const q = req.validated.query;
      const data = await activityService.projectTimeline(
        { ...q, from: q.from ? new Date(q.from) : undefined, to: q.to ? new Date(q.to) : undefined },
        req.user,
      );
      res.status(200).json({ data });
    },
  };
}

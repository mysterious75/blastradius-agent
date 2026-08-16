const express = require('express');
const _ = require('lodash');
const app = express();

app.post('/merge', (req, res) => {
  const options = {};
  _.merge(options, req.body);
  res.json({ ok: true });
});

app.listen(3000);

const express = require("express");
const router = express.Router();

const aiRouter = require("../ai/aiRouter");

router.use("/", aiRouter);

module.exports = router;
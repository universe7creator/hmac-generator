const crypto = require('crypto');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-License-Key');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { message, secret, algorithm = 'sha256', encoding = 'hex' } = req.body || {};

    if (!message || !secret) {
      return res.status(400).json({
        error: 'Missing required fields',
        details: 'Both message and secret are required'
      });
    }

    // Validate algorithm
    const validAlgorithms = ['sha256', 'sha512', 'sha1', 'md5'];
    if (!validAlgorithms.includes(algorithm)) {
      return res.status(400).json({
        error: 'Invalid algorithm',
        validAlgorithms
      });
    }

    // Generate HMAC
    const hmac = crypto.createHmac(algorithm, secret);
    hmac.update(message);
    const result = encoding === 'base64' ? hmac.digest('base64') : hmac.digest('hex');

    return res.status(200).json({
      success: true,
      hmac: result,
      algorithm,
      encoding,
      messageLength: message.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    return res.status(500).json({
      error: 'HMAC generation failed',
      details: error.message
    });
  }
};

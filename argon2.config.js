// argon2.config.js
self.ARGON2_PRESETS = {
  interactive: { m: 64,  t: 2, p: 1 },
  balanced:    { m: 256, t: 3, p: 2 },
  high:        { m: 512, t: 3, p: 2 }
};

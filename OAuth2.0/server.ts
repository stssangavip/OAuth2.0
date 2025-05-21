// server.ts or app.ts

import config from './src/config/config';
import tokenRoutes from './src/routes/routes';
import express, { Request, Response } from 'express';

const app = express();

// Middleware
app.use(express.json());

// Routes
app.use('/', tokenRoutes);





// Start server
app.listen(config.port, () => {
  console.log(`🚀 Server running on port ${config.port}`);
});

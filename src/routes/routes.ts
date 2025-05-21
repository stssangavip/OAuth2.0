import express, { Request, Response, NextFunction } from 'express';
import { generateTokens ,accessverifed,VerifedAuthentication,RegisterWebHook} from '../controllers/OAuthController';

const router = express.Router();

router.post('/oauth/token', (req: Request, res: Response, next: NextFunction) => {
	generateTokens(req, res).catch(next);
});
router.get('/oauth/authorize', (req: Request, res: Response, next: NextFunction) => {
	accessverifed(req, res).catch(next);
});
	router.get('/me', (req: Request, res: Response, next: NextFunction) => {
	VerifedAuthentication(req, res).catch(next);
});
	router.post('oauth/RegisterWebHook', (req: Request, res: Response, next: NextFunction) => {
	RegisterWebHook(req, res).catch(next);
});
export default router;

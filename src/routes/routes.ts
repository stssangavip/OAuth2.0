import express, { Request, Response, NextFunction } from 'express';
import { generateTokens ,accessverifed,VerifedAuthentication,SubcribeWebHook,UnSubcribeWebHook} from '../controllers/OAuthController';

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
	router.post('/oauth/SubcribeWebHook', (req: Request, res: Response, next: NextFunction) => {
	SubcribeWebHook(req, res).catch(next);
});
router.post('/oauth/UnSubcribeWebHook', (req: Request, res: Response, next: NextFunction) => {
	UnSubcribeWebHook(req, res).catch(next);
});
export default router;

from typing import Dict, Any
import httpx
from fastapi import HTTPException, status
from app.core.config import settings


class OAuthService:
    """Service for OAuth integration with email providers"""
    
    GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
    GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
    
    MICROSOFT_AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    MICROSOFT_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    MICROSOFT_USERINFO_URL = "https://graph.microsoft.com/v1.0/me"
    
    YAHOO_AUTH_URL = "https://api.login.yahoo.com/oauth2/request_auth"
    YAHOO_TOKEN_URL = "https://api.login.yahoo.com/oauth2/get_token"
    YAHOO_USERINFO_URL = "https://api.login.yahoo.com/openid/v1/userinfo"
    
    @staticmethod
    def get_google_auth_url() -> str:
        """Get Google OAuth authorization URL"""
        params = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly",
            "access_type": "offline",
            "prompt": "consent"
        }
        
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{OAuthService.GOOGLE_AUTH_URL}?{query_string}"
    
    @staticmethod
    def get_microsoft_auth_url() -> str:
        """Get Microsoft OAuth authorization URL"""
        params = {
            "client_id": settings.MICROSOFT_CLIENT_ID,
            "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile Mail.Read offline_access",
            "response_mode": "query"
        }
        
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{OAuthService.MICROSOFT_AUTH_URL}?{query_string}"
    
    @staticmethod
    def get_yahoo_auth_url() -> str:
        """Get Yahoo OAuth authorization URL"""
        params = {
            "client_id": settings.YAHOO_CLIENT_ID,
            "redirect_uri": settings.YAHOO_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile"
        }
        
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{OAuthService.YAHOO_AUTH_URL}?{query_string}"
    
    @staticmethod
    async def exchange_google_code(code: str) -> Dict[str, Any]:
        """Exchange Google authorization code for tokens"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                OAuthService.GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code"
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to exchange code for token"
                )
            
            return response.json()
    
    @staticmethod
    async def exchange_microsoft_code(code: str) -> Dict[str, Any]:
        """Exchange Microsoft authorization code for tokens"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                OAuthService.MICROSOFT_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": settings.MICROSOFT_CLIENT_ID,
                    "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                    "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
                    "grant_type": "authorization_code"
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to exchange code for token"
                )
            
            return response.json()
    
    @staticmethod
    async def exchange_yahoo_code(code: str) -> Dict[str, Any]:
        """Exchange Yahoo authorization code for tokens"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                OAuthService.YAHOO_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": settings.YAHOO_CLIENT_ID,
                    "client_secret": settings.YAHOO_CLIENT_SECRET,
                    "redirect_uri": settings.YAHOO_REDIRECT_URI,
                    "grant_type": "authorization_code"
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to exchange code for token"
                )
            
            return response.json()
    
    @staticmethod
    async def get_google_user_info(access_token: str) -> Dict[str, Any]:
        """Get Google user information"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                OAuthService.GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to get user info"
                )
            
            return response.json()
    
    @staticmethod
    async def get_microsoft_user_info(access_token: str) -> Dict[str, Any]:
        """Get Microsoft user information"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                OAuthService.MICROSOFT_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to get user info"
                )
            
            return response.json()
    
    @staticmethod
    async def get_yahoo_user_info(access_token: str) -> Dict[str, Any]:
        """Get Yahoo user information"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                OAuthService.YAHOO_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to get user info"
                )
            
            return response.json()


oauth_service = OAuthService()

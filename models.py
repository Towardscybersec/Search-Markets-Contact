from pydantic import BaseModel, Field
from typing import Optional


class Socials(BaseModel):
    """Social media links for a place/business"""
    facebook: Optional[str] = None
    instagram: Optional[str] = None
    twitter: Optional[str] = None
    linkedin: Optional[str] = None


class Place(BaseModel):
    """Data model for a Google Maps place/business"""
    title: str
    rating: Optional[float] = None
    reviews_count: Optional[int] = None
    category: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    socials: Socials = Field(default_factory=Socials)


class ScrapeResponse(BaseModel):
    """Response model for scrape endpoint"""
    query: str
    total_results: int
    places: list[Place]

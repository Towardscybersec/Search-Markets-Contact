import time
import re
from urllib.parse import parse_qs, unquote, urlparse, urlunparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from models import Place


class GoogleMapsScraper:
    """Scraper for extracting business information from Google Maps"""
    
    def __init__(self):
        self.driver = None
    
    def setup_driver(self):
        """Initialize headless Chrome driver"""
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument("user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
        
        self.driver = webdriver.Chrome(options=chrome_options)
        return self.driver
    
    def scroll_results(self, max_wait=60):
        """Scroll until 'You've reached the end of the list.' appears or no new results load for a while."""
        try:
            scrollable_div = self.driver.find_element(By.CSS_SELECTOR, 'div[role="feed"]')
            last_height = 0
            start_time = time.time()
            while True:
                # Scroll to bottom
                self.driver.execute_script('arguments[0].scrollTo(0, arguments[0].scrollHeight)', scrollable_div)
                time.sleep(0.7)
                # Check for end-of-list message
                try:
                    end_elem = self.driver.find_element(By.XPATH, "//*[contains(text(), \"You've reached the end of the list.\")]")
                    if end_elem.is_displayed():
                        print("Reached end of list message.")
                        break
                except NoSuchElementException:
                    pass
                # Check if new results loaded
                new_height = self.driver.execute_script('return arguments[0].scrollHeight', scrollable_div)
                if new_height == last_height:
                    # If no new results for a while, stop
                    if time.time() - start_time > max_wait:
                        print("No new results loaded for a while. Stopping scroll.")
                        break
                else:
                    last_height = new_height
                    start_time = time.time()  # Reset timer if new results
        except NoSuchElementException:
            print("Could not find scrollable results feed")

    def _resolve_redirect_url(self, url: str) -> str:
        if not url:
            return url
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            if "google.com" in netloc and parsed.path == "/url":
                query = parse_qs(parsed.query)
                target = query.get("q", [None])[0] or query.get("url", [None])[0]
                if target:
                    return unquote(target)
            if "facebook.com" in netloc and parsed.path.endswith("/l.php"):
                target = parse_qs(parsed.query).get("u", [None])[0]
                if target:
                    return unquote(target)
        except Exception:
            return url
        return url

    def _clean_url(self, url: str) -> str:
        if not url:
            return url
        cleaned = url.strip().strip("'\"")
        cleaned = cleaned.replace("&amp;", "&").replace("\\u0026", "&")
        return cleaned

    def _host_matches(self, host: str, domain: str) -> bool:
        host = (host or "").lower().split(":")[0]
        return host == domain or host.endswith(f".{domain}")

    def _path_segments(self, path: str) -> list[str]:
        return [segment for segment in unquote(path or "").split("/") if segment]

    def _is_valid_facebook_path(self, path: str) -> bool:
        segments = self._path_segments(path)
        if not segments:
            return False

        first = segments[0].lower()
        blocked = {
            "about",
            "dialog",
            "help",
            "legal",
            "login",
            "plugins",
            "policy",
            "policy.php",
            "privacy",
            "recover",
            "sharer",
            "sharer.php",
            "share.php",
            "terms",
        }
        return first not in blocked

    def _is_valid_instagram_path(self, path: str) -> bool:
        segments = self._path_segments(path)
        if not segments:
            return False

        first = segments[0].lower()
        blocked = {
            "about",
            "accounts",
            "developer",
            "directory",
            "explore",
            "legal",
            "p",
            "privacy",
            "reel",
            "reels",
            "stories",
            "terms",
            "tv",
        }
        return first not in blocked

    def _is_valid_twitter_path(self, path: str) -> bool:
        segments = self._path_segments(path)
        if not segments:
            return False

        first = segments[0].lower()
        blocked = {
            "compose",
            "explore",
            "hashtag",
            "home",
            "i",
            "intent",
            "login",
            "privacy",
            "search",
            "settings",
            "share",
            "signup",
            "tos",
        }
        return first not in blocked

    def _is_valid_linkedin_path(self, path: str) -> bool:
        segments = self._path_segments(path)
        if len(segments) < 2:
            return False

        first = segments[0].lower()
        allowed = {"company", "in", "pub", "school", "showcase"}
        if first not in allowed:
            return False

        blocked_anywhere = {"admin", "authwall", "detail", "feed", "posts", "recent-activity"}
        return all(segment.lower() not in blocked_anywhere for segment in segments[1:])

    def _normalize_social_url(self, platform: str, url: str) -> str | None:
        if not url:
            return None

        resolved = self._resolve_redirect_url(self._clean_url(url))
        try:
            parsed = urlparse(resolved)
        except Exception:
            return None

        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            return None

        netloc = (parsed.netloc or "").lower()
        if not netloc:
            return None

        if platform == "facebook":
            if not self._host_matches(netloc, "facebook.com") or not self._is_valid_facebook_path(parsed.path):
                return None
        elif platform == "instagram":
            if not self._host_matches(netloc, "instagram.com") or not self._is_valid_instagram_path(parsed.path):
                return None
        elif platform == "twitter":
            if not (self._host_matches(netloc, "twitter.com") or self._host_matches(netloc, "x.com")):
                return None
            if not self._is_valid_twitter_path(parsed.path):
                return None
        elif platform == "linkedin":
            if not self._host_matches(netloc, "linkedin.com") or not self._is_valid_linkedin_path(parsed.path):
                return None
        else:
            return None

        normalized_path = parsed.path.rstrip("/")
        if not normalized_path:
            return None

        scheme = parsed.scheme if parsed.scheme else "https"
        return urlunparse((scheme, parsed.netloc, normalized_path, "", "", ""))

    def _extract_socials_from_text(self, socials: dict, text: str) -> None:
        if not text:
            return

        patterns = {
            "facebook": re.compile(r"https?://(?:www\.)?(?:m\.)?facebook\.com/[^\s\"'<>]+", re.IGNORECASE),
            "instagram": re.compile(r"https?://(?:www\.)?instagram\.com/[^\s\"'<>]+", re.IGNORECASE),
            "twitter": re.compile(r"https?://(?:www\.)?(?:twitter\.com|x\.com)/[^\s\"'<>]+", re.IGNORECASE),
            "linkedin": re.compile(r"https?://(?:www\.)?linkedin\.com/[^\s\"'<>]+", re.IGNORECASE),
        }

        for key, pattern in patterns.items():
            if socials.get(key):
                continue
            for match in pattern.finditer(text):
                normalized = self._normalize_social_url(key, match.group(0))
                if normalized:
                    socials[key] = normalized
                    break

    def _update_socials_from_href(self, socials: dict, href: str) -> None:
        if not href:
            return
        for platform in ("facebook", "instagram", "twitter", "linkedin"):
            if socials.get(platform):
                continue
            normalized = self._normalize_social_url(platform, href)
            if normalized:
                socials[platform] = normalized
                break

    def extract_socials_from_website(self, website_url: str) -> dict:
        socials = {
            "facebook": None,
            "instagram": None,
            "twitter": None,
            "linkedin": None,
        }

        if not website_url:
            return socials

        target_url = self._resolve_redirect_url(website_url)
        original_window = self.driver.current_window_handle
        new_window = None

        try:
            self.driver.execute_script("window.open(arguments[0], '_blank');", target_url)
            WebDriverWait(self.driver, 5).until(lambda driver: len(driver.window_handles) > 1)
            for handle in self.driver.window_handles:
                if handle != original_window:
                    new_window = handle
                    break

            if not new_window:
                return socials

            self.driver.switch_to.window(new_window)
            WebDriverWait(self.driver, 5).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            time.sleep(0.5)

            links = self.driver.find_elements(By.TAG_NAME, "a")
            for link in links:
                for attr in ("href", "data-href", "data-url"):
                    href = link.get_attribute(attr)
                    self._update_socials_from_href(socials, href)

            page_source = self.driver.page_source
            self._extract_socials_from_text(socials, page_source)

        except Exception:
            pass
        finally:
            try:
                if new_window and new_window in self.driver.window_handles:
                    self.driver.switch_to.window(new_window)
                    self.driver.close()
            except Exception:
                pass
            try:
                self.driver.switch_to.window(original_window)
            except Exception:
                pass

        return socials
    
    def extract_place_data_from_details(self) -> dict:
        """Extract detailed information from the expanded place details panel"""
        place_data = {
            "title": None,
            "rating": None,
            "reviews_count": None,
            "category": None,
            "address": None,
            "phone": None,
            "website": None,
            "socials": {
                "facebook": None,
                "instagram": None,
                "twitter": None,
                "linkedin": None,
            },
        }
        
        try:
            # Wait for details panel to load
            WebDriverWait(self.driver, 5).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'h1'))
            )
            time.sleep(0.5)  # Extra wait for content to stabilize
        except TimeoutException:
            return place_data
        
        try:
            # Title
            title_elem = self.driver.find_element(By.CSS_SELECTOR, 'h1.DUwDvf')
            place_data["title"] = title_elem.text.strip()
        except NoSuchElementException:
            pass
        
        try:
            # Rating and reviews count
            rating_elem = self.driver.find_element(By.CSS_SELECTOR, 'div.F7nice span[aria-hidden="true"]')
            rating_text = rating_elem.text.strip()
            if rating_text:
                place_data["rating"] = float(rating_text.replace(",", "."))
            
            # Reviews count
            reviews_elem = self.driver.find_element(By.CSS_SELECTOR, 'div.F7nice span[aria-label*="review"]')
            reviews_text = reviews_elem.get_attribute("aria-label")
            reviews_num = ''.join(filter(str.isdigit, reviews_text))
            if reviews_num:
                place_data["reviews_count"] = int(reviews_num)
        except (NoSuchElementException, ValueError):
            pass
        
        try:
            # Category
            category_elem = self.driver.find_element(By.CSS_SELECTOR, 'button[jsaction*="category"]')
            place_data["category"] = category_elem.text.strip()
        except NoSuchElementException:
            pass
        
        try:
            # Address - look for aria-label containing "Address"
            address_elem = self.driver.find_element(By.CSS_SELECTOR, 'button[data-item-id="address"]')
            address_text = address_elem.get_attribute("aria-label")
            if address_text:
                # Remove "Address: " prefix
                place_data["address"] = address_text.replace("Address:", "").strip()
        except NoSuchElementException:
            pass
        
        try:
            # Phone - look for aria-label containing "Phone"
            phone_elem = self.driver.find_element(By.CSS_SELECTOR, 'button[data-item-id*="phone"]')
            phone_text = phone_elem.get_attribute("aria-label")
            if phone_text:
                # Remove "Phone: " prefix
                place_data["phone"] = phone_text.replace("Phone:", "").strip()
        except NoSuchElementException:
            pass
        
        try:
            # Website - look for aria-label containing "Website"
            website_elem = self.driver.find_element(By.CSS_SELECTOR, 'a[data-item-id="authority"]')
            place_data["website"] = website_elem.get_attribute("href")
        except NoSuchElementException:
            pass

        try:
            # Social links directly visible in Maps panel
            social_links = self.driver.find_elements(
                By.CSS_SELECTOR,
                'a[href*="facebook.com"],'
                'a[href*="instagram.com"],'
                'a[href*="twitter.com"],'
                'a[href*="x.com"],'
                'a[href*="linkedin.com"]'
            )

            for link in social_links:
                href = link.get_attribute("href")
                self._update_socials_from_href(place_data["socials"], href)
        except NoSuchElementException:
            pass

        if place_data["website"] and any(value is None for value in place_data["socials"].values()):
            website_socials = self.extract_socials_from_website(place_data["website"])
            for key, value in website_socials.items():
                if value and not place_data["socials"].get(key):
                    place_data["socials"][key] = value

        return place_data
    
    def scrape(self, query: str) -> list[Place]:
        """
        Main scraping method
        
        Args:
            query: Search term (e.g., "restaurants in NYC")
            
        Returns:
            List of Place objects with extracted data
        """
        places = []
        
        try:
            self.setup_driver()
            
            # Navigate to Google Maps with search query
            url = f"https://www.google.com/maps/search/{query.replace(' ', '+')}"
            self.driver.get(url)
            
            # Wait for results to load
            try:
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, 'div[role="feed"]'))
                )
            except TimeoutException:
                print("Timeout waiting for results to load")
                return places
            
            # Scroll to load more results
            self.scroll_results()
            
            # Wait a bit for final content to settle
            time.sleep(1)
            
            # Find all place links and collect their URLs
            place_links = self.driver.find_elements(
                By.CSS_SELECTOR, 
                'div[role="feed"] a[href*="/maps/place/"]'
            )
            
            # Extract URLs from the links to avoid stale element issues
            place_urls = []
            for link in place_links:
                try:
                    url = link.get_attribute("href")
                    if url and url not in place_urls:  # Avoid duplicates
                        place_urls.append(url)
                except:
                    continue
            
            print(f"Found {len(place_urls)} unique places to scrape")
            
            # Navigate to each place URL and extract detailed information
            for i, url in enumerate(place_urls):
                try:
                    self.driver.get(url)
                    time.sleep(1.5)
                    place_data = self.extract_place_data_from_details()
                    if place_data.get("title"):
                        place = Place(**place_data)
                        places.append(place)
                        print(f"Scraped {i+1}/{len(place_urls)}: {place.title}")
                except Exception as e:
                    print(f"Error processing place {i+1}: {e}")
                    continue
            
        except Exception as e:
            print(f"Scraping error: {e}")
        finally:
            if self.driver:
                self.driver.quit()
        
        return places


def scrape_google_maps(query: str) -> list[Place]:
    """Convenience function to scrape Google Maps"""
    scraper = GoogleMapsScraper()
    return scraper.scrape(query)

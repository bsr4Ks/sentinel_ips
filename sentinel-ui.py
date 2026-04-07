import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import logging
from typing import Dict, List, Any, Optional
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ========== CONFIGURATION ==========
class Config:
    """Centralized configuration."""
    SERVER_IP = os.getenv("SERVER_IP")
    API_URL = f"http://{SERVER_IP}:4446"
    API_TIMEOUT = 5
    GEO_API_URL = "http://ip-api.com/json"
    GEO_MAX_IPS = 20
    GEO_TIMEOUT = 5
    
    # UI Theme
    THEME_BG_COLOR = "#0e1117"
    THEME_TEXT_COLOR = "#ffffff"
    PAGE_TITLE = "Sentinel SOC"
    PAGE_LAYOUT = "wide"
    PAGE_ICON = "🛡️"


# ========== LOGGING ==========
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ========== API CLIENT ==========
class APIClient:
    """Handles API communication."""
    
    def __init__(self, base_url: str, timeout: int):
        self.base_url = base_url
        self.timeout = timeout
    
    def get_stats(self) -> Optional[Dict[str, Any]]:
        """Fetch statistics from API."""
        try:
            response = requests.get(f"{self.base_url}/stats", timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            logger.error("Stats request timed out")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch stats: {e}")
            return None
    
    def get_latest_hits(self, limit: int = 100) -> Optional[List[Dict[str, Any]]]:
        """Fetch latest attack hits from API."""
        try:
            response = requests.get(
                f"{self.base_url}/latest-hits?limit={limit}",
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            logger.error("Latest hits request timed out")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch latest hits: {e}")
            return None


# ========== GEOLOCATION SERVICE ==========
class GeoLocationService:
    """Handles geolocation data retrieval."""
    
    def __init__(self, api_url: str, timeout: int, max_ips: int):
        self.api_url = api_url
        self.timeout = timeout
        self.max_ips = max_ips
    
    def get_location_data(self, ip_list: List[str]) -> pd.DataFrame:
        """Fetch location data for IP addresses."""
        locations = []
        
        for ip in ip_list[:self.max_ips]:
            try:
                response = requests.get(f"{self.api_url}/{ip}", timeout=self.timeout).json()
                if response.get('status') == 'success':
                    locations.append({
                        'ip': ip,
                        'lat': response.get('lat'),
                        'lon': response.get('lon'),
                        'country': response.get('country')
                    })
            except Exception as e:
                logger.warning(f"Failed to get location for {ip}: {e}")
                continue
        
        return pd.DataFrame(locations)


# ========== UI COMPONENTS ==========
class UITheme:
    """Manages UI theme and styling."""
    
    @staticmethod
    def apply_theme():
        """Apply dark theme to Streamlit app."""
        st.markdown(f"""
            <style>
            .main {{ background-color: {Config.THEME_BG_COLOR}; color: {Config.THEME_TEXT_COLOR}; }}
            </style>
            """, unsafe_allow_html=True)


class Dashboard:
    """Handles dashboard UI rendering."""
    
    @staticmethod
    def display_header():
        """Display main header."""
        st.title(f"{Config.PAGE_ICON} Sentinel IPS | Security Operations Center")
        st.caption(f"Connected to Frankfurt Node: {Config.SERVER_IP}")
    
    @staticmethod
    def display_stats_metrics(stats: Dict[str, Any]):
        """Display statistics metrics."""
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Bans", stats.get('total_incidents', 0), delta_color="inverse")
        with col2:
            st.metric("Unique Attackers", stats.get('unique_attackers', 0), delta_color="inverse")
        with col3:
            st.metric("Node Status", "ACTIVE 🟢")
    
    @staticmethod
    def display_threat_distribution(df: pd.DataFrame):
        """Display threat distribution chart."""
        if df.empty or 'reason' not in df.columns:
            return
        
        reason_counts = df['reason'].value_counts().reset_index()
        reason_counts.columns = ['reason', 'count']
        
        fig = px.bar(
            reason_counts,
            x='reason',
            y='count',
            labels={'reason': 'Attack Type', 'count': 'Frequency'},
            color='reason',
            template="plotly_dark"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    @staticmethod
    def display_live_feed(df: pd.DataFrame):
        """Display live feed of attacks."""
        if df.empty:
            return
        
        required_cols = [col for col in ['ip', 'reason', 'timestamp'] if col in df.columns]
        display_df = df[required_cols].sort_values(by='timestamp', ascending=False)
        st.dataframe(display_df, height=400, use_container_width=True)
    
    @staticmethod
    def display_global_map(location_df: pd.DataFrame):
        """Display global attack origins map."""
        if location_df.empty:
            st.info("No geolocation data available")
            return
        
        fig_map = px.scatter_geo(
            location_df,
            lat='lat',
            lon='lon',
            hover_name='ip',
            color='country',
            projection="natural earth",
            title="Attacker Locations"
        )
        st.plotly_chart(fig_map, use_container_width=True)


# ========== MAIN APPLICATION ==========
def configure_page():
    """Configure Streamlit page."""
    st.set_page_config(
        page_title=Config.PAGE_TITLE,
        layout=Config.PAGE_LAYOUT,
        page_icon=Config.PAGE_ICON
    )
    UITheme.apply_theme()


def main():
    """Main application entry point."""
    configure_page()
    Dashboard.display_header()
    
    # Initialize API client
    logger.info(f"Connecting to API at {Config.API_URL}")
    api_client = APIClient(Config.API_URL, Config.API_TIMEOUT)
    
    # Fetch data
    stats = api_client.get_stats()
    hits = api_client.get_latest_hits(limit=100)
    
    # Handle errors
    if stats is None or hits is None:
        st.error(
            f"📡 Connection Failed! Check if API is running on server.\n"
            f"Endpoint: {Config.API_URL}"
        )
        return
    
    df = pd.DataFrame(hits)
    
    # Display stats
    Dashboard.display_stats_metrics(stats)
    
    # Display threat analysis
    if not df.empty:
        left_col, right_col = st.columns([2, 1])
        
        with left_col:
            st.subheader("📊 Threat Distribution")
            Dashboard.display_threat_distribution(df)
        
        with right_col:
            st.subheader("💀 Live Feed")
            Dashboard.display_live_feed(df)
    
    # Display geolocation map
    st.subheader("🌐 Global Attack Origins")
    geo_service = GeoLocationService(
        Config.GEO_API_URL,
        Config.GEO_TIMEOUT,
        Config.GEO_MAX_IPS
    )
    location_df = geo_service.get_location_data(df['ip'].unique().tolist() if not df.empty else [])
    Dashboard.display_global_map(location_df)


if __name__ == "__main__":
    main()
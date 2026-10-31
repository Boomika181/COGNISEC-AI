from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple


def utc_now():
    return datetime.now(timezone.utc)


class GeoLocationService:
    """
    Privacy-Preserving Geolocation Resolution Service.
    - Handles explicit user-granted GPS coordinates.
    - Resolves approximate IP-derived location without inferring fake GPS precision.
    - Never collects or stores precise coordinates when permission is denied or ungranted.
    """

    @classmethod
    def resolve_location(
        cls,
        ip_address: Optional[str] = None,
        client_lat: Optional[float] = None,
        client_lon: Optional[float] = None,
        client_accuracy: Optional[float] = None,
        client_source: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Determines the best available geographic evidence for the login session.
        """
        now = utc_now()
        source = (client_source or "").upper()

        # 1. User Explicitly Granted GPS Location
        if client_lat is not None and client_lon is not None and (
            source in ("GPS", "BROWSER_GEOLOCATION") or "GEO" in source or not source
        ):
            acc_str = f" ±{int(client_accuracy)}m" if client_accuracy else ""
            return {
                "latitude": round(client_lat, 5),
                "longitude": round(client_lon, 5),
                "city": None,
                "region": None,
                "country": None,
                "location_source": client_source or "BROWSER_GEOLOCATION",
                "location_accuracy": client_accuracy,
                "location_updated_at": now,
                "summary": f"GPS Coordinates ({round(client_lat, 3)}, {round(client_lon, 3)}{acc_str})",
                "privacy_note": "Precise location provided with explicit user browser permission."
            }

        # 2. Location Permission Denied by User
        if "DENIED" in source:
            return {
                "latitude": None,
                "longitude": None,
                "city": None,
                "region": None,
                "country": None,
                "location_source": "PERMISSION_DENIED",
                "location_accuracy": None,
                "location_updated_at": now,
                "summary": "Location permission declined by user",
                "privacy_note": "User declined browser geolocation prompt. Continuing with privacy safeguards."
            }

        # 3. Location Service Unavailable or Unsupported
        if "UNAVAILABLE" in source or "TIMED_OUT" in source:
            return {
                "latitude": None,
                "longitude": None,
                "city": None,
                "region": None,
                "country": None,
                "location_source": client_source or "UNAVAILABLE",
                "location_accuracy": None,
                "location_updated_at": now,
                "summary": "Browser geolocation unavailable",
                "privacy_note": "Device or browser context does not support geolocation."
            }

        # 4. Approximate IP-Derived Location Fallback
        ip = (ip_address or "127.0.0.1").strip()
        is_private_ip = any(ip.startswith(prefix) for prefix in [
            "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
            "172.31.", "::1", "localhost"
        ])

        if is_private_ip:
            return {
                "latitude": None,
                "longitude": None,
                "city": "Local Network",
                "region": "Intranet",
                "country": "Localhost",
                "location_source": "IP_APPROXIMATE",
                "location_accuracy": None,
                "location_updated_at": now,
                "summary": f"Local Development Network (IP {ip})",
                "privacy_note": "Local/loopback network address. No public geographic lookup performed."
            }

        # External Public IP: Approximate location only (Never infer precise GPS)
        return {
            "latitude": None,
            "longitude": None,
            "city": "Approximate City",
            "region": "Approximate Region",
            "country": "Approximate Country",
            "location_source": "IP_APPROXIMATE",
            "location_accuracy": None,
            "location_updated_at": now,
            "summary": f"Approximate IP Location (IP {ip})",
            "privacy_note": "Approximate location derived from public IP address. Never precise."
        }

    @staticmethod
    def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        import math
        r = 6371.0  # Earth radius in kilometers
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)
        a = (math.sin(delta_phi / 2.0) ** 2 +
             math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2)
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return r * c

    @classmethod
    def check_implausible_travel(
        cls,
        lat1: Optional[float],
        lon1: Optional[float],
        time1: Optional[datetime],
        lat2: Optional[float],
        lon2: Optional[float],
        time2: Optional[datetime],
        max_speed_kmh: float = 900.0,
        min_distance_km: float = 200.0
    ) -> Tuple[bool, float, float]:
        """
        Determines whether transit between two geographic locations exceeds physical travel limits.
        Returns: (is_implausible, distance_km, speed_kmh)
        """
        if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
            return False, 0.0, 0.0
        if time1 is None or time2 is None:
            return False, 0.0, 0.0

        dist_km = cls.haversine_distance_km(lat1, lon1, lat2, lon2)
        if dist_km < min_distance_km:
            return False, dist_km, 0.0

        dt_seconds = abs((time2 - time1).total_seconds())
        if dt_seconds <= 0:
            return True, dist_km, 99999.0

        dt_hours = dt_seconds / 3600.0
        speed_kmh = dist_km / dt_hours

        is_implausible = speed_kmh > max_speed_kmh
        return is_implausible, round(dist_km, 2), round(speed_kmh, 2)


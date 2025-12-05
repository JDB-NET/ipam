"""
In-memory caching module with TTL support and cache invalidation
"""
import time
import sys
from threading import Lock
from functools import wraps

class Cache:
    """Simple in-memory cache with TTL support and size limiting"""
    
    def __init__(self, max_size_mb=50):
        self._cache = {}
        self._lock = Lock()
        self._max_size_bytes = max_size_mb * 1024 * 1024  # Convert MB to bytes
        self._access_order = []  # Track access order for LRU eviction
    
    def _get_size(self, obj):
        """Estimate size of an object in bytes"""
        size = sys.getsizeof(obj)
        if isinstance(obj, dict):
            size += sum(self._get_size(k) + self._get_size(v) for k, v in obj.items())
        elif isinstance(obj, (list, tuple)):
            size += sum(self._get_size(item) for item in obj)
        elif isinstance(obj, str):
            size += sys.getsizeof(obj) - sys.getsizeof('')
        return size
    
    def _get_cache_size(self):
        """Get approximate total size of cache in bytes"""
        total_size = sys.getsizeof(self._cache)
        for key, (value, expiry) in self._cache.items():
            total_size += self._get_size(key) + self._get_size(value) + sys.getsizeof(expiry)
        return total_size
    
    def _evict_if_needed(self):
        """Evict entries if cache exceeds size limit"""
        current_size = self._get_cache_size()
        if current_size <= self._max_size_bytes:
            return
        
        # First, remove expired entries
        current_time = time.time()
        expired_keys = []
        for key in list(self._cache.keys()):
            _, expiry = self._cache[key]
            if expiry is not None and current_time >= expiry:
                expired_keys.append(key)
        
        for key in expired_keys:
            if key in self._cache:
                del self._cache[key]
            if key in self._access_order:
                self._access_order.remove(key)
        
        # If still over limit, remove oldest entries (LRU)
        current_size = self._get_cache_size()
        while current_size > self._max_size_bytes and self._access_order:
            oldest_key = self._access_order.pop(0)
            if oldest_key in self._cache:
                del self._cache[oldest_key]
                current_size = self._get_cache_size()
    
    def get(self, key):
        """Get value from cache if it exists and hasn't expired"""
        with self._lock:
            if key in self._cache:
                value, expiry = self._cache[key]
                if expiry is None or time.time() < expiry:
                    # Update access order (move to end for LRU)
                    if key in self._access_order:
                        self._access_order.remove(key)
                    self._access_order.append(key)
                    return value
                else:
                    # Expired, remove it
                    del self._cache[key]
                    if key in self._access_order:
                        self._access_order.remove(key)
            return None
    
    def set(self, key, value, ttl=None):
        """Set value in cache with optional TTL (time to live in seconds)"""
        with self._lock:
            # Remove old entry if it exists
            if key in self._cache:
                if key in self._access_order:
                    self._access_order.remove(key)
            
            expiry = None if ttl is None else time.time() + ttl
            self._cache[key] = (value, expiry)
            self._access_order.append(key)
            
            # Evict if needed to stay under size limit
            self._evict_if_needed()
    
    def delete(self, key):
        """Delete a key from cache"""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
            if key in self._access_order:
                self._access_order.remove(key)
    
    def clear(self, pattern=None):
        """Clear cache entries. If pattern is provided, only clear keys matching the pattern."""
        with self._lock:
            if pattern is None:
                self._cache.clear()
                self._access_order.clear()
            else:
                keys_to_delete = [key for key in self._cache.keys() if pattern in key]
                for key in keys_to_delete:
                    del self._cache[key]
                    if key in self._access_order:
                        self._access_order.remove(key)
    
    def invalidate_subnet(self, subnet_id):
        """Invalidate all cache entries related to a specific subnet"""
        patterns = [
            f'subnet:{subnet_id}',
            f'subnet_list',
            f'index',
            f'admin',
            f'utilization:{subnet_id}'
        ]
        with self._lock:
            keys_to_delete = []
            for key in self._cache.keys():
                for pattern in patterns:
                    if pattern in key:
                        keys_to_delete.append(key)
                        break
            for key in keys_to_delete:
                del self._cache[key]
                if key in self._access_order:
                    self._access_order.remove(key)
    
    def invalidate_device(self, device_id):
        """Invalidate all cache entries related to a specific device"""
        patterns = [
            f'device:{device_id}',
            f'device_list',
            f'devices',
            f'device_types'
        ]
        with self._lock:
            keys_to_delete = []
            for key in self._cache.keys():
                for pattern in patterns:
                    if pattern in key:
                        keys_to_delete.append(key)
                        break
            for key in keys_to_delete:
                del self._cache[key]
                if key in self._access_order:
                    self._access_order.remove(key)
    
    def invalidate_all(self):
        """Invalidate all cache entries"""
        self.clear()

# Global cache instance
cache = Cache()

def cached(ttl=None, key_prefix=''):
    """
    Decorator to cache function results
    
    Args:
        ttl: Time to live in seconds (None = no expiration)
        key_prefix: Prefix for cache key
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from function name, args, and kwargs
            cache_key = f"{key_prefix}{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
            
            # Try to get from cache
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            # Call function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            return result
        return wrapper
    return decorator


import { describe, it, expect, vi } from 'vitest';
import { login, fetchStats, fetchLogs } from '../services/api';

// Mock the global fetch
global.fetch = vi.fn();

describe('API Services', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('login() should return success on valid credentials', async () => {
    const mockResponse = { success: true, token: 'fake-token' };
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    });

    const result = await login('admin', '1234');
    expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('/login'), expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ username: 'admin', password: '1234' })
    }));
    expect(result).toBe(true);
  });

  it('fetchStats() should return stats data', async () => {
    const mockStats = { total_predictions: 100, mode: 'dataset' };
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => mockStats,
    });

    const result = await fetchStats();
    expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining('/stats'));
    expect(result).toEqual(mockStats);
  });

  it('fetchLogs() should handle errors gracefully', async () => {
    (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));
    
    const result = await fetchLogs();
    expect(result.logs).toBeInstanceOf(Array);
    expect(result.last_id).toBeGreaterThanOrEqual(0);
  });
});

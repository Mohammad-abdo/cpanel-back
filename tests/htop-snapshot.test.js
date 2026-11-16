import { describe, expect, it } from 'vitest';
import { cpuUsageFromSnaps, parseHtopSnapshot } from '../src/modules/server-access/server-access.service.js';

describe('htop snapshot parser', () => {
  it('computes CPU usage from two /proc/stat samples', () => {
    const a = ['cpu  100 0 100 800 0 0 0 0', 'cpu0 50 0 50 400 0 0 0 0'];
    const b = ['cpu  200 0 200 900 0 0 0 0', 'cpu0 100 0 100 450 0 0 0 0'];
    const rows = cpuUsageFromSnaps(a, b);
    const all = rows.find((r) => r.id === 'cpu');
    expect(all.usage).toBeGreaterThan(40);
    expect(all.usage).toBeLessThan(70);
  });

  it('parses labelled HTOP_SCRIPT output', () => {
    const text = [
      '##hostname',
      'lab-1',
      '##uptime',
      '3661.2',
      '##load',
      '0.50 0.40 0.30 1/200 1',
      '##cpus',
      '2',
      '##mem',
      '8000000000 2000000000 1000000000 500000000 5500000000',
      '##swap',
      '1000000000 100000000',
      '##tasks',
      '120',
      '##cpusnap1',
      'cpu  100 0 100 800 0 0 0 0',
      'cpu0 50 0 50 400 0 0 0 0',
      '##cpusnap2',
      'cpu  200 0 200 900 0 0 0 0',
      'cpu0 100 0 100 450 0 0 0 0',
      '##procs',
      '  1 root     S  0.0  0.1  12000  1-00:01:02 systemd /sbin/init',
      ' 42 www-data R 12.5  2.0  80000    00:02 nginx: worker process',
    ].join('\n');

    const snap = parseHtopSnapshot(text);
    expect(snap.hostname).toBe('lab-1');
    expect(snap.uptimeSec).toBe(3661);
    expect(snap.load.m1).toBe(0.5);
    expect(snap.cpuCount).toBe(2);
    expect(snap.memory.total).toBe(8000000000);
    expect(snap.swap.used).toBe(100000000);
    expect(snap.taskCount).toBe(120);
    expect(snap.cpu.all).toBeTypeOf('number');
    expect(snap.processes).toHaveLength(2);
    expect(snap.processes[1]).toMatchObject({ pid: 42, user: 'www-data', state: 'R', command: 'nginx:' });
  });
});

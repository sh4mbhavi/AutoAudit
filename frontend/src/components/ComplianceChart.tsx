import Chart from 'react-apexcharts';
import type { ApexOptions } from 'apexcharts';
import type { ScanAssessmentFields, ScanResultStatus } from '../types/scan';
import { getScanAssessment, RESULT_LABELS } from '../utils/scanAssessment';

type ChartScan = ScanAssessmentFields & { id: number | string; status?: string | null };
type Props = {
  isDarkMode?: boolean;
  chartType?: 'doughnut' | 'pie' | 'bar';
  scan?: ScanAssessmentFields | null;
  scans?: ChartScan[];
};

export default function ComplianceChart({ isDarkMode = true, chartType = 'doughnut', scan, scans = [] }: Props) {
  const history = scans.filter((s) => s.status === 'completed').slice(0, 8).reverse();
  const states = Object.keys(RESULT_LABELS) as ScanResultStatus[];
  const counts = getScanAssessment(scan || {}).counts;
  const values = states.map((state) => counts[state]);
  const isBar = chartType === 'bar';
  const options: ApexOptions = {
    chart: { background: 'transparent', toolbar: { show: false }, animations: { enabled: false } },
    theme: { mode: isDarkMode ? 'dark' : 'light' },
    colors: isBar ? ['#10b981', '#3b82f6'] : ['#10b981', '#ef4444', '#eab308', '#f97316', '#94a3b8', '#64748b', '#3b82f6'],
    labels: states.map((state) => RESULT_LABELS[state]),
    legend: { position: 'bottom' },
    dataLabels: { enabled: false },
    xaxis: { categories: history.map((s) => `#${s.id}`) },
    yaxis: isBar ? { min: 0, max: 100, labels: { formatter: (value) => `${value}%` } } : undefined,
    tooltip: { y: { formatter: (value) => value == null ? 'Not assessed' : `${value}${isBar ? '%' : ' controls'}` } },
  };
  const series = isBar ? [
    { name: 'Compliance among assessed', data: history.map((s) => { const a = getScanAssessment(s); return a.legacy ? null : a.compliance; }) },
    { name: 'Automated coverage', data: history.map((s) => getScanAssessment(s).coverage) },
  ] : values;
  if (isBar ? history.length === 0 : values.every((value) => value === 0)) {
    return <div className="flex h-full items-center justify-center text-sm">No scan results available</div>;
  }
  const unassessed = history.filter((s) => !getScanAssessment(s).legacy && getScanAssessment(s).compliance === null);
  return (
    <div className="flex h-full flex-col" aria-label="Scan results chart">
      <div className="min-h-0 flex-1">
        <Chart options={options} series={series} type={isBar ? 'bar' : chartType === 'doughnut' ? 'donut' : 'pie'} height="100%" />
      </div>
      {isBar && history.some((s) => getScanAssessment(s).legacy) && <p className="text-xs">Legacy scans have no comparable coverage or compliance series.</p>}
      {isBar && unassessed.length > 0 && <p className="text-xs">Not assessed: {unassessed.map((s) => `#${s.id}`).join(', ')}</p>}
    </div>
  );
}

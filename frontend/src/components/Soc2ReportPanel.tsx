import React, { useCallback, useEffect, useState } from "react";
import { AlertCircle, FileText, Loader2 } from "lucide-react";

import { getSoc2Report } from "../api/client";
import type {
	Soc2Coverage,
	Soc2PointOfFocus,
	Soc2ReportResponse,
} from "../types/soc2";

/**
 * The SOC 2 projection for one scan.
 *
 * `GET /v1/scans/{id}/soc2-report` has existed since Phase 4 with 34 backend
 * tests behind it and no caller at all: `types/soc2.ts` typed the entire
 * response and `api/client.ts` had no function to fetch it, so the report a
 * reviewer is meant to read could not be reached from the product.
 *
 * What this renders, it renders on the terms the response states:
 *
 * - `configuration_rating` is a human GRC judgment copied verbatim from the
 *   pinned mapping. `rating_is_computed` is always false and nothing here may
 *   derive, promote or override it.
 * - coverage is never shown as a bare percentage. `assessed_count` and
 *   `applicable_count` are both displayed, and `coverage_statement` is printed
 *   as written.
 * - manual residual evidence and drift are separate streams, both carrying
 *   `counted_in_automated_coverage: false`, and are shown beside the automated
 *   figures rather than added to them.
 * - `not_a_certification` is displayed with the report and is never suppressed.
 *
 * Two limits are surfaced rather than hidden, because they are real and a
 * reviewer needs to know them: this endpoint is **owner-scoped only**, so the
 * auditor role that gates cross-owner review elsewhere does not apply, and the
 * response carries **no identifier for the tenant** it describes -- only the
 * scan's.
 */

type Soc2ReportPanelProps = {
	scanId: string | number;
	isDarkMode: boolean;
};

const ratingTone = (rating: string): string => {
	const normalised = rating.trim().toLowerCase();
	if (normalised === "yes") return "bg-emerald-500/15 text-emerald-500";
	if (normalised === "partial") return "bg-amber-500/15 text-amber-500";
	if (normalised === "no") return "bg-red-500/15 text-red-500";
	return "bg-slate-500/15 text-slate-400";
};

const CoverageFigures: React.FC<{ coverage: Soc2Coverage; muted: string }> = ({
	coverage,
	muted,
}) => (
	<div className="flex flex-col gap-1">
		{/* Numerator and denominator together, never a percentage on its own. */}
		<p className={`m-0 text-sm ${muted}`}>
			{coverage.assessed_count} of {coverage.applicable_count} applicable
			control(s) assessed
			{coverage.partial_assessment ? " (partial)" : ""}
		</p>
		<p className={`m-0 text-xs ${muted}`}>{coverage.coverage_statement}</p>
	</div>
);

const PointOfFocusRow: React.FC<{
	point: Soc2PointOfFocus;
	textPrimary: string;
	muted: string;
	tertiaryBg: string;
}> = ({ point, textPrimary, muted, tertiaryBg }) => (
	<div className={`rounded-lg p-4 ${tertiaryBg}`}>
		<div className="flex gap-3 justify-between items-start max-md:flex-col max-md:gap-2">
			<div className="flex-1">
				<p className={`m-0 text-xs font-mono ${muted}`}>
					{point.criterion} · {point.point_id}
				</p>
				<h4 className={`m-0 mt-1 text-sm font-medium ${textPrimary}`}>
					{point.point_of_focus}
				</h4>
			</div>
			<span
				className={`rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide max-md:self-start ${ratingTone(
					point.configuration_rating,
				)}`}
				title="Copied verbatim from the pinned crosswalk. Scan results never change it."
			>
				{point.configuration_rating}
			</span>
		</div>
		<div className="mt-3">
			<CoverageFigures coverage={point.coverage} muted={muted} />
		</div>
		{!point.selector_resolved && (
			<p className="mt-2 m-0 text-xs text-amber-500">
				Evidence selector was not resolved, so this point's coverage is
				incomplete.
			</p>
		)}
		{point.manual_residual_evidence.length > 0 && (
			<p className={`mt-2 m-0 text-xs ${muted}`}>
				{point.manual_residual_evidence.length} approved manual
				record(s), reported separately and not added to the coverage
				above.
			</p>
		)}
		{point.limitations.residual_limitation && (
			<p className={`mt-2 m-0 text-xs italic ${muted}`}>
				{point.limitations.residual_limitation}
			</p>
		)}
	</div>
);

const Soc2ReportPanel: React.FC<Soc2ReportPanelProps> = ({
	scanId,
	isDarkMode,
}) => {
	const [report, setReport] = useState<Soc2ReportResponse | null>(null);
	const [isLoading, setIsLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [isOpen, setIsOpen] = useState(false);

	const cardBg = isDarkMode
		? "border-white/10 bg-white/5"
		: "border-slate-200 bg-white";
	const tertiaryBg = isDarkMode ? "bg-white/5" : "bg-slate-50";
	const textPrimary = isDarkMode ? "text-white" : "text-slate-900";
	const muted = isDarkMode ? "text-slate-400" : "text-slate-500";

	const load = useCallback(
		async (signal: AbortSignal) => {
			setIsLoading(true);
			setError(null);
			try {
				setReport(await getSoc2Report(scanId, { signal }));
			} catch (loadError) {
				if (signal.aborted) return;
				setError(
					loadError instanceof Error
						? loadError.message
						: "The SOC 2 report could not be loaded.",
				);
			} finally {
				if (!signal.aborted) setIsLoading(false);
			}
		},
		[scanId],
	);

	useEffect(() => {
		if (!isOpen || report || error) return;
		const controller = new AbortController();
		void load(controller.signal);
		return () => controller.abort();
	}, [isOpen, report, error, load]);

	return (
		<div className={`rounded-xl border p-6 ${cardBg}`} data-testid="soc2-report">
			<div className="flex gap-3 justify-between items-center">
				<h2 className={`text-lg font-semibold m-0 ${textPrimary}`}>
					<FileText size={18} className="inline mr-2 align-[-3px]" />
					SOC 2 report
				</h2>
				<button
					type="button"
					onClick={() => setIsOpen((open) => !open)}
					className="rounded-lg border border-current/20 px-3 py-1.5 text-sm font-medium text-blue-500"
				>
					{isOpen ? "Hide" : "Show"}
				</button>
			</div>

			{isOpen && (
				<div className="mt-5 flex flex-col gap-4">
					{isLoading && (
						<p className={`flex gap-2 items-center m-0 text-sm ${muted}`}>
							<Loader2 size={16} className="animate-spin" />
							Loading the projection…
						</p>
					)}

					{error && (
						<p className="flex gap-2 items-start m-0 text-sm text-red-500">
							<AlertCircle size={16} className="shrink-0" />
							{error}
						</p>
					)}

					{report && !report.projection_available && (
						<p className={`m-0 text-sm ${muted}`}>{report.message}</p>
					)}

					{report?.projection_available && report.header && (
						<>
							{/* Never suppressed: this is the sentence that keeps
							    the report from reading as an attestation. */}
							<p className="m-0 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-600">
								{report.header.not_a_certification}
							</p>
							<p className={`m-0 text-xs ${muted}`}>
								{report.header.rating_ownership}
							</p>
							{report.header.approval_pending && (
								<p className="m-0 text-xs text-amber-500">
									The pinned crosswalk has not been approved by
									a named reviewer.
								</p>
							)}
							<p className={`m-0 text-xs ${muted}`}>
								Scoped to the account that owns this scan. The
								report identifies the scan, not the tenant it
								describes.
							</p>

							{report.manual_evidence_stream && (
								<p className={`m-0 text-xs ${muted}`}>
									{report.manual_evidence_stream.note}
								</p>
							)}
							{report.drift_stream && (
								<p className={`m-0 text-xs ${muted}`}>
									{report.drift_stream.note}
								</p>
							)}

							<div className="flex flex-col gap-3">
								{(report.points_of_focus ?? []).map((point) => (
									<PointOfFocusRow
										key={point.point_id}
										point={point}
										textPrimary={textPrimary}
										muted={muted}
										tertiaryBg={tertiaryBg}
									/>
								))}
							</div>

							{(report.mapping_resolution_findings ?? []).length >
								0 && (
								<div className="flex flex-col gap-1">
									<h3
										className={`m-0 text-sm font-semibold ${textPrimary}`}
									>
										Mapping resolution findings
									</h3>
									{report.mapping_resolution_findings?.map(
										(finding) => (
											<p
												key={`${finding.code}:${finding.control_id}`}
												className={`m-0 text-xs ${muted}`}
											>
												{finding.control_id}:{" "}
												{finding.detail}
											</p>
										),
									)}
								</div>
							)}
						</>
					)}
				</div>
			)}
		</div>
	);
};

export default Soc2ReportPanel;

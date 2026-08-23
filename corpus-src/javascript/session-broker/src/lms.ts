/**
 * Learning-management integration.
 *
 * The broker mirrors course rosters so that session policy can be resolved
 * without a round trip to the upstream system on every request. Nothing here
 * performs, selects or configures cryptography: the roster is fetched over the
 * transport the platform already established, and no key material reaches this
 * module.
 *
 * This file carries no ground-truth entry, deliberately. What it tests, and why,
 * is recorded in docs/pending-review.md entry 11. The explanation is kept there
 * rather than here on purpose, so that no cryptographic name appears anywhere in
 * this file.
 */

import { Settings } from "./settings.js";

export interface Enrolment {
  courseId: string;
  learnerId: string;
  role: "learner" | "instructor" | "observer";
}

export interface RosterPage {
  enrolments: Enrolment[];
  nextCursor?: string;
}

/** Client for the upstream learning-management system. */
export class LmsClient {
  private readonly baseUrl: string;
  private readonly tenant: string;

  constructor(settings: Settings) {
    this.baseUrl = settings.lmsBaseUrl;
    this.tenant = settings.lmsTenant;
  }

  /** Fetch one page of the course roster. */
  async fetchRoster(courseId: string, cursor?: string): Promise<RosterPage> {
    const url = new URL(`/api/v2/courses/${courseId}/enrolments`, this.baseUrl);
    url.searchParams.set("tenant", this.tenant);
    if (cursor) {
      url.searchParams.set("cursor", cursor);
    }

    const response = await fetch(url, { headers: { accept: "application/json" } });
    if (!response.ok) {
      throw new Error(`lms roster fetch failed: ${response.status}`);
    }
    return (await response.json()) as RosterPage;
  }

  /** Fetch every page of the course roster. */
  async fetchAllEnrolments(courseId: string): Promise<Enrolment[]> {
    const all: Enrolment[] = [];
    let cursor: string | undefined;
    do {
      const page = await this.fetchRoster(courseId, cursor);
      all.push(...page.enrolments);
      cursor = page.nextCursor;
    } while (cursor);
    return all;
  }
}

/** Resolve the session policy a learner's enrolments imply. */
export function policyForEnrolments(enrolments: Enrolment[]): string {
  if (enrolments.some((e) => e.role === "instructor")) {
    return "extended";
  }
  if (enrolments.length === 0) {
    return "guest";
  }
  return "standard";
}

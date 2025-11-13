import { NotificationsService } from '../dashboard-api/src/notifications/notifications.service';
import { UnifiedFindingsService } from '../dashboard-api/src/unified-findings/unified-findings.service';

/**
 * Score Monitor Service
 * Monitors compliance score changes and triggers notifications
 */
export class ScoreMonitorService {
  constructor(
    private readonly notificationsService: NotificationsService,
    private readonly findingsService: UnifiedFindingsService
  ) {}

  /**
   * Check for score drops and send notifications
   * This should be called after finding updates
   */
  async checkScoreChanges(userId: string, applicationIds?: string[], teamNames?: string[]): Promise<void> {
    try {
      // Get current dashboard data
      const dashboard = await this.findingsService.getDeveloperDashboard(applicationIds, teamNames);

      // Check if score dropped
      if (dashboard.trend === 'down' && dashboard.scoreChange < 0) {
        // Get user's applications/teams to determine who to notify
        // For now, notify the user who made the change
        // In a real system, you'd notify all users associated with the applications/teams
        
        await this.notificationsService.notifyScoreDrop(
          userId,
          dashboard.scoreChange,
          dashboard.previousScore,
          dashboard.currentScore,
          applicationIds?.[0],
          teamNames?.[0]
        );
      }
    } catch (error) {
      console.error('Error checking score changes:', error);
    }
  }

  /**
   * Check for new critical findings
   */
  async checkCriticalFindings(userId: string, findingId: string, findingTitle: string): Promise<void> {
    try {
      const finding = await this.findingsService.getFindingById(findingId);
      if (finding && finding.severity === 'critical') {
        await this.notificationsService.notifyCriticalFinding(userId, findingId, findingTitle);
      }
    } catch (error) {
      console.error('Error checking critical findings:', error);
    }
  }
}


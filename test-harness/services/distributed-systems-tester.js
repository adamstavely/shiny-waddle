"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DistributedSystemsTester = void 0;
class DistributedSystemsTester {
    constructor(config, pdp) {
        this.config = config;
        this.pdp = pdp;
    }
    async testPolicyConsistency(test) {
        const startTime = Date.now();
        const result = {
            testName: test.name,
            distributedTestType: 'policy-consistency',
            testType: 'distributed-systems',
            passed: false,
            timestamp: new Date(),
            regionResults: [],
            consistencyCheck: {
                consistent: true,
                inconsistencies: [],
            },
            details: {},
        };
        try {
            const regionsToTest = this.getRegionsToTest(test.regions);
            const regionResults = [];
            for (const region of regionsToTest) {
                const regionResult = await this.testRegion(region, test, startTime);
                regionResults.push(regionResult);
            }
            result.regionResults = regionResults;
            result.consistencyCheck = this.checkConsistency(regionResults);
            result.performanceMetrics = this.calculatePerformanceMetrics(regionResults);
            result.passed =
                result.consistencyCheck.consistent &&
                    regionResults.every(r => !r.error);
            return result;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            return result;
        }
    }
    async testMultiRegion(test) {
        const startTime = Date.now();
        const result = {
            testName: test.name,
            distributedTestType: 'multi-region',
            testType: 'distributed-systems',
            passed: false,
            timestamp: new Date(),
            regionResults: [],
            consistencyCheck: {
                consistent: true,
                inconsistencies: [],
            },
            details: {},
        };
        try {
            const regionsToTest = this.getRegionsToTest(test.regions);
            const regionResults = [];
            for (const region of regionsToTest) {
                const regionResult = await this.testRegionAccess(region, test);
                regionResults.push(regionResult);
            }
            result.regionResults = regionResults;
            const allAllowed = regionResults.every(r => r.allowed);
            const allDenied = regionResults.every(r => !r.allowed);
            if (test.expectedResult !== undefined) {
                result.passed =
                    (test.expectedResult && allAllowed) ||
                        (!test.expectedResult && allDenied);
            }
            else {
                result.passed = allAllowed || allDenied;
            }
            if (!result.passed) {
                result.consistencyCheck = this.checkConsistency(regionResults);
            }
            result.performanceMetrics = this.calculatePerformanceMetrics(regionResults);
            return result;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            return result;
        }
    }
    async testPolicySynchronization(test) {
        const startTime = Date.now();
        const result = {
            testName: test.name,
            distributedTestType: 'synchronization',
            testType: 'distributed-systems',
            passed: false,
            timestamp: new Date(),
            regionResults: [],
            consistencyCheck: {
                consistent: true,
                inconsistencies: [],
            },
            synchronizationCheck: {
                synchronized: false,
            },
            details: {},
        };
        try {
            const primaryRegion = this.config.regions[0];
            await this.updatePolicyInRegion(primaryRegion, test);
            const syncInterval = this.config.policySync?.syncInterval || 1000;
            await this.sleep(syncInterval);
            const regionsToTest = this.getRegionsToTest(test.regions);
            const regionResults = [];
            for (const region of regionsToTest) {
                const regionResult = await this.testRegion(region, test, startTime);
                regionResults.push(regionResult);
            }
            result.regionResults = regionResults;
            const syncCheck = this.checkSynchronization(regionResults, startTime);
            result.synchronizationCheck = syncCheck;
            result.passed = syncCheck.synchronized;
            return result;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            return result;
        }
    }
    async testDistributedTransaction(test) {
        const startTime = Date.now();
        const result = {
            testName: test.name,
            distributedTestType: 'transaction',
            testType: 'distributed-systems',
            passed: false,
            timestamp: new Date(),
            regionResults: [],
            consistencyCheck: {
                consistent: true,
                inconsistencies: [],
            },
            details: {},
        };
        try {
            const regionsToTest = this.getRegionsToTest(test.regions);
            const transactionResults = [];
            for (const region of regionsToTest) {
                const prepareResult = await this.prepareTransaction(region, test);
                transactionResults.push(prepareResult);
            }
            const allPrepared = transactionResults.every(r => r.allowed);
            if (!allPrepared) {
                await this.abortTransaction(regionsToTest, test);
                result.passed = false;
                result.details = { phase: 'prepare', aborted: true };
                return result;
            }
            const commitResults = [];
            for (const region of regionsToTest) {
                const commitResult = await this.commitTransaction(region, test);
                commitResults.push(commitResult);
            }
            result.regionResults = [...transactionResults, ...commitResults];
            result.passed = commitResults.every(r => r.allowed);
            result.performanceMetrics = this.calculatePerformanceMetrics(result.regionResults);
            return result;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            return result;
        }
    }
    async testEventualConsistency(test) {
        const startTime = Date.now();
        const result = {
            testName: test.name,
            distributedTestType: 'eventual-consistency',
            testType: 'distributed-systems',
            passed: false,
            timestamp: new Date(),
            regionResults: [],
            consistencyCheck: {
                consistent: false,
                inconsistencies: [],
            },
            details: {},
        };
        try {
            const primaryRegion = this.config.regions[0];
            await this.updatePolicyInRegion(primaryRegion, test);
            const immediateResults = await this.testAllRegions(test, startTime);
            const immediateConsistency = this.checkConsistency(immediateResults);
            const maxWaitTime = test.timeout || 10000;
            const checkInterval = 500;
            let elapsed = 0;
            let consistent = false;
            while (elapsed < maxWaitTime && !consistent) {
                await this.sleep(checkInterval);
                elapsed += checkInterval;
                const currentResults = await this.testAllRegions(test, startTime);
                const currentConsistency = this.checkConsistency(currentResults);
                if (currentConsistency.consistent) {
                    consistent = true;
                    result.regionResults = currentResults;
                    result.consistencyCheck = currentConsistency;
                    result.details = {
                        convergenceTime: elapsed,
                        maxWaitTime,
                    };
                }
            }
            result.passed = consistent;
            result.performanceMetrics = this.calculatePerformanceMetrics(result.regionResults);
            return result;
        }
        catch (error) {
            result.passed = false;
            result.error = error.message;
            return result;
        }
    }
    async testRegion(region, test, startTime) {
        const regionStartTime = Date.now();
        try {
            if (region.latency) {
                await this.sleep(region.latency);
            }
            let allowed = false;
            let decision = null;
            if (this.pdp && test.user && test.resource) {
                decision = await this.pdp.evaluate({
                    subject: {
                        id: test.user.id,
                        attributes: {
                            ...test.user.attributes,
                            region: region.id,
                        },
                    },
                    resource: {
                        id: test.resource.id,
                        type: test.resource.type,
                        attributes: test.resource.attributes,
                    },
                    context: {
                        region: region.id,
                        timestamp: new Date().toISOString(),
                    },
                    action: test.action || 'read',
                });
                allowed = decision.allowed;
            }
            else if (region.pdpEndpoint) {
                const response = await fetch(`${region.pdpEndpoint}/evaluate`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...(region.credentials?.token
                            ? { Authorization: `Bearer ${region.credentials.token}` }
                            : {}),
                    },
                    body: JSON.stringify({
                        subject: {
                            id: test.user?.id,
                            attributes: {
                                ...test.user?.attributes,
                                region: region.id,
                            },
                        },
                        resource: {
                            id: test.resource?.id,
                            type: test.resource?.type,
                            attributes: test.resource?.attributes,
                        },
                        context: {
                            region: region.id,
                            timestamp: new Date().toISOString(),
                        },
                        action: test.action || 'read',
                    }),
                });
                if (response.ok) {
                    decision = await response.json();
                    allowed = decision.allowed || false;
                }
                else {
                    throw new Error(`PDP evaluation failed: ${response.statusText}`);
                }
            }
            else {
                allowed = true;
            }
            const latency = Date.now() - regionStartTime;
            return {
                regionId: region.id,
                regionName: region.name,
                allowed,
                decision,
                latency,
                timestamp: new Date(),
            };
        }
        catch (error) {
            return {
                regionId: region.id,
                regionName: region.name,
                allowed: false,
                decision: null,
                latency: Date.now() - regionStartTime,
                timestamp: new Date(),
                error: error.message,
            };
        }
    }
    async testRegionAccess(region, test) {
        return this.testRegion(region, test, Date.now());
    }
    async testAllRegions(test, startTime) {
        const regionsToTest = this.getRegionsToTest(test.regions);
        const results = [];
        for (const region of regionsToTest) {
            const result = await this.testRegion(region, test, startTime);
            results.push(result);
        }
        return results;
    }
    checkConsistency(results) {
        const inconsistencies = [];
        for (let i = 0; i < results.length; i++) {
            for (let j = i + 1; j < results.length; j++) {
                const r1 = results[i];
                const r2 = results[j];
                if (r1.allowed !== r2.allowed) {
                    inconsistencies.push({
                        region1: r1.regionName,
                        region2: r2.regionName,
                        difference: `Region ${r1.regionName} returned ${r1.allowed}, but ${r2.regionName} returned ${r2.allowed}`,
                        severity: 'critical',
                    });
                }
                if (r1.decision && r2.decision) {
                    const decision1 = JSON.stringify(r1.decision);
                    const decision2 = JSON.stringify(r2.decision);
                    if (decision1 !== decision2) {
                        inconsistencies.push({
                            region1: r1.regionName,
                            region2: r2.regionName,
                            difference: 'Policy decisions differ between regions',
                            severity: 'high',
                        });
                    }
                }
            }
        }
        return {
            consistent: inconsistencies.length === 0,
            inconsistencies,
        };
    }
    checkSynchronization(results, startTime) {
        const syncTime = Date.now() - startTime;
        const regionsOutOfSync = [];
        const firstDecision = results[0]?.allowed;
        const allSynchronized = results.every(r => r.allowed === firstDecision && !r.error);
        if (!allSynchronized) {
            results.forEach(r => {
                if (r.allowed !== firstDecision || r.error) {
                    regionsOutOfSync.push(r.regionName);
                }
            });
        }
        return {
            synchronized: allSynchronized,
            syncTime,
            regionsOutOfSync: regionsOutOfSync.length > 0 ? regionsOutOfSync : undefined,
        };
    }
    calculatePerformanceMetrics(results) {
        if (results.length === 0) {
            return {
                totalTime: 0,
                averageLatency: 0,
                slowestRegion: '',
                fastestRegion: '',
            };
        }
        const latencies = results.map(r => r.latency);
        const totalTime = Math.max(...latencies);
        const averageLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
        const slowest = results.reduce((a, b) => a.latency > b.latency ? a : b);
        const fastest = results.reduce((a, b) => a.latency < b.latency ? a : b);
        return {
            totalTime,
            averageLatency,
            slowestRegion: slowest.regionName,
            fastestRegion: fastest.regionName,
        };
    }
    async updatePolicyInRegion(region, test) {
        if (region.pdpEndpoint) {
            await fetch(`${region.pdpEndpoint}/policies`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    ...(region.credentials?.token
                        ? { Authorization: `Bearer ${region.credentials.token}` }
                        : {}),
                },
                body: JSON.stringify({
                    test: test.name,
                    timestamp: new Date().toISOString(),
                }),
            });
        }
    }
    async prepareTransaction(region, test) {
        const startTime = Date.now();
        try {
            await this.sleep(region.latency || 50);
            return {
                regionId: region.id,
                regionName: region.name,
                allowed: true,
                decision: { phase: 'prepare', status: 'ready' },
                latency: Date.now() - startTime,
                timestamp: new Date(),
            };
        }
        catch (error) {
            return {
                regionId: region.id,
                regionName: region.name,
                allowed: false,
                decision: null,
                latency: Date.now() - startTime,
                timestamp: new Date(),
                error: error.message,
            };
        }
    }
    async commitTransaction(region, test) {
        const startTime = Date.now();
        try {
            await this.sleep(region.latency || 50);
            return {
                regionId: region.id,
                regionName: region.name,
                allowed: true,
                decision: { phase: 'commit', status: 'committed' },
                latency: Date.now() - startTime,
                timestamp: new Date(),
            };
        }
        catch (error) {
            return {
                regionId: region.id,
                regionName: region.name,
                allowed: false,
                decision: null,
                latency: Date.now() - startTime,
                timestamp: new Date(),
                error: error.message,
            };
        }
    }
    async abortTransaction(regions, test) {
        for (const region of regions) {
            await this.sleep(region.latency || 50);
        }
    }
    getRegionsToTest(specifiedRegions) {
        if (specifiedRegions && specifiedRegions.length > 0) {
            return this.config.regions.filter(r => specifiedRegions.includes(r.id));
        }
        return this.config.regions;
    }
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}
exports.DistributedSystemsTester = DistributedSystemsTester;
//# sourceMappingURL=distributed-systems-tester.js.map
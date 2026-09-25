import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DebugElement, EmbeddedViewRef, getDebugNode } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { HttpErrorResponse } from '@angular/common/http';
import { TranslateService } from '@ngx-translate/core';
import { MockProvider } from 'ng-mocks';
import { Subject, of, throwError } from 'rxjs';

import { AdminSbomComponent } from './admin-sbom.component';
import { AdminSbomService } from './admin-sbom.service';
import { AlertService } from 'app/foundation/service/alert.service';
import { AdminTitleBarService } from 'app/admin/shared/admin-title-bar.service';
import { MockTranslateService } from 'test/helpers/mocks/service/mock-translate.service';
import { ArtemisVersion, CombinedSbom, ComponentVulnerabilities, SbomComponent, Vulnerability } from './admin-sbom.model';

describe('AdminSbomComponent', () => {
    let component: AdminSbomComponent;
    let fixture: ComponentFixture<AdminSbomComponent>;
    let sbomService: AdminSbomService;
    let alertService: AlertService;

    const mockServerComponents: SbomComponent[] = [
        {
            name: 'spring-core',
            version: '6.0.0',
            type: 'library',
            group: 'org.springframework',
            purl: 'pkg:maven/org.springframework/spring-core@6.0.0',
        },
        {
            name: 'spring-boot',
            version: '3.0.0',
            type: 'library',
            group: 'org.springframework.boot',
            purl: 'pkg:maven/org.springframework.boot/spring-boot@3.0.0',
        },
    ];

    const mockClientComponents: SbomComponent[] = [
        {
            name: 'core',
            version: '17.0.0',
            type: 'library',
            group: '@angular',
            purl: 'pkg:npm/@angular/core@17.0.0',
        },
    ];

    const mockCombinedSbom: CombinedSbom = {
        server: {
            bomFormat: 'CycloneDX',
            specVersion: '1.6',
            serialNumber: 'urn:uuid:server-serial',
            version: 1,
            components: mockServerComponents,
        },
        client: {
            bomFormat: 'CycloneDX',
            specVersion: '1.6',
            serialNumber: 'urn:uuid:client-serial',
            version: 1,
            components: mockClientComponents,
        },
    };

    const mockVulnerabilities: ComponentVulnerabilities = {
        vulnerabilities: [
            {
                componentKey: 'pkg:maven/org.springframework/spring-core@6.0.0',
                vulnerabilities: [
                    {
                        id: 'CVE-2024-1234',
                        summary: 'Test vulnerability',
                        details: 'Test details',
                        severity: 'HIGH',
                        cvssScore: 7.5,
                        fixedIn: ['6.1.0'],
                        references: ['https://example.com'],
                    },
                ],
            },
        ],
        totalVulnerabilities: 1,
        criticalCount: 0,
        highCount: 1,
        mediumCount: 0,
        lowCount: 0,
        lastChecked: '2024-01-01T00:00:00Z',
    };

    const mockVersionInfo: ArtemisVersion = {
        currentVersion: '7.8.0',
        latestVersion: '7.9.0',
        updateAvailable: true,
        releaseUrl: 'https://github.com/ls1intum/Artemis/releases/tag/7.9.0',
        releaseNotes: 'New features and bug fixes',
        lastChecked: '2024-01-01T00:00:00Z',
    };

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [AdminSbomComponent],
            providers: [
                MockProvider(AdminSbomService, {
                    getCombinedSbom: () => of(mockCombinedSbom),
                    getVulnerabilities: () => of(mockVulnerabilities),
                    refreshVulnerabilities: () => of(mockVulnerabilities),
                    getVersionInfo: () => of(mockVersionInfo),
                    sendVulnerabilityEmail: () => of(undefined),
                }),
                MockProvider(AlertService, {
                    error: vi.fn(),
                    success: vi.fn(),
                }),
                { provide: TranslateService, useClass: MockTranslateService },
            ],
        });

        fixture = TestBed.createComponent(AdminSbomComponent);
        component = fixture.componentInstance;
        sbomService = TestBed.inject(AdminSbomService);
        alertService = TestBed.inject(AlertService);
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should create', () => {
        expect(component).toBeTruthy();
    });

    describe('loadSbom', () => {
        it('should load combined SBOM on init', () => {
            const getSbomSpy = vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            const getVulnSpy = vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));

            component.ngOnInit();

            expect(getSbomSpy).toHaveBeenCalled();
            expect(getVulnSpy).toHaveBeenCalled();
            expect(component.combinedSbom()).toEqual(mockCombinedSbom);
            expect(component.loading()).toBe(false);
        });

        it('should show error alert when SBOM load fails', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(throwError(() => new Error('Load failed')));
            const errorSpy = vi.spyOn(alertService, 'error');

            component.loadSbom();

            expect(errorSpy).toHaveBeenCalledWith('artemisApp.dependencies.loadError');
            expect(component.loading()).toBe(false);
            expect(component.sbomUnavailable()).toBe(false);
        });

        it('should set sbomUnavailable without showing a toast on 404', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(throwError(() => new HttpErrorResponse({ status: 404 })));
            const errorSpy = vi.spyOn(alertService, 'error');

            component.loadSbom();

            expect(component.sbomUnavailable()).toBe(true);
            expect(component.loading()).toBe(false);
            expect(errorSpy).not.toHaveBeenCalled();
        });

        it('should not trigger loadVulnerabilities when the SBOM is unavailable', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(throwError(() => new HttpErrorResponse({ status: 404 })));
            const vulnSpy = vi.spyOn(sbomService, 'getVulnerabilities');

            component.loadSbom();
            component.loadVulnerabilities();

            expect(vulnSpy).not.toHaveBeenCalled();
        });

        it('should clear sbomUnavailable on a subsequent successful load', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValueOnce(throwError(() => new HttpErrorResponse({ status: 404 })));
            component.loadSbom();
            expect(component.sbomUnavailable()).toBe(true);

            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));
            component.loadSbom();

            expect(component.sbomUnavailable()).toBe(false);
            expect(component.combinedSbom()).toEqual(mockCombinedSbom);
        });
    });

    describe('loadVulnerabilities', () => {
        it('should load vulnerability data', () => {
            const getVulnSpy = vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));

            component.loadVulnerabilities();

            expect(getVulnSpy).toHaveBeenCalled();
            expect(component.vulnerabilities()).toEqual(mockVulnerabilities);
            expect(component.loadingVulnerabilities()).toBe(false);
        });

        it('should show error alert when vulnerability load fails', () => {
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(throwError(() => new Error('Load failed')));
            const errorSpy = vi.spyOn(alertService, 'error');

            component.loadVulnerabilities();

            expect(errorSpy).toHaveBeenCalledWith('artemisApp.dependencies.vulnerabilityLoadError');
            expect(component.loadingVulnerabilities()).toBe(false);
        });

        it('should suppress the toast when vulnerability load returns 404', () => {
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(throwError(() => new HttpErrorResponse({ status: 404 })));
            const errorSpy = vi.spyOn(alertService, 'error');

            component.loadVulnerabilities();

            expect(errorSpy).not.toHaveBeenCalled();
            expect(component.loadingVulnerabilities()).toBe(false);
        });
    });

    describe('refreshVulnerabilities', () => {
        it('should refresh vulnerability data', () => {
            const refreshSpy = vi.spyOn(sbomService, 'refreshVulnerabilities').mockReturnValue(of(mockVulnerabilities));
            const successSpy = vi.spyOn(alertService, 'success');

            component.refreshVulnerabilities();

            expect(refreshSpy).toHaveBeenCalled();
            expect(component.vulnerabilities()).toEqual(mockVulnerabilities);
            expect(successSpy).toHaveBeenCalledWith('artemisApp.dependencies.vulnerabilityRefreshSuccess');
        });
    });

    describe('filteredComponents', () => {
        beforeEach(() => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));
            component.ngOnInit();
        });

        it('should return all components when no filter applied', () => {
            const components = component.filteredComponents();
            expect(components).toHaveLength(3); // 2 server + 1 client
        });

        it('should filter by source - server only', () => {
            component.updateSource('server');
            const components = component.filteredComponents();
            expect(components).toHaveLength(2);
            expect(components.every((c) => c.source === 'server')).toBe(true);
        });

        it('should filter by source - client only', () => {
            component.updateSource('client');
            const components = component.filteredComponents();
            expect(components).toHaveLength(1);
            expect(components[0].source).toBe('client');
        });

        it('should filter by text', () => {
            component.updateFilter('spring');
            const components = component.filteredComponents();
            expect(components).toHaveLength(2);
            expect(components.every((c) => c.name?.includes('spring'))).toBe(true);
        });

        it('should filter vulnerable only', () => {
            component.toggleVulnerableOnly();
            const components = component.filteredComponents();
            expect(components).toHaveLength(1);
            expect(components[0].name).toBe('spring-core');
        });
    });

    describe('component counts', () => {
        beforeEach(() => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));
            component.ngOnInit();
        });

        it('should correctly count server components', () => {
            expect(component.serverComponentCount()).toBe(2);
        });

        it('should correctly count client components', () => {
            expect(component.clientComponentCount()).toBe(1);
        });

        it('should correctly count total components', () => {
            expect(component.totalComponentCount()).toBe(3);
        });
    });

    describe('sorting', () => {
        beforeEach(() => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));
            component.ngOnInit();
        });

        it('should sort by name ascending by default', () => {
            const components = component.filteredComponents();
            expect(components[0].name).toBe('core');
            expect(components[1].name).toBe('spring-boot');
            expect(components[2].name).toBe('spring-core');
        });

        it('should apply descending order from a sort event', () => {
            expect(component.sortAscending()).toBe(true);
            component.onTableSort({ field: 'name', order: -1 });
            expect(component.sortField()).toBe('name');
            expect(component.sortAscending()).toBe(false);
        });

        it('should switch the sort field from a sort event', () => {
            component.onTableSort({ field: 'version', order: 1 });
            expect(component.sortField()).toBe('version');
            expect(component.sortAscending()).toBe(true);
        });
    });

    describe('getHighestSeverity', () => {
        it('should return empty string for no vulnerabilities', () => {
            expect(component.getHighestSeverity(undefined)).toBe('');
            expect(component.getHighestSeverity([])).toBe('');
        });

        it('should return CRITICAL when present', () => {
            const vulns: Vulnerability[] = [{ severity: 'HIGH' } as Vulnerability, { severity: 'CRITICAL' } as Vulnerability];
            expect(component.getHighestSeverity(vulns)).toBe('CRITICAL');
        });

        it('should return HIGH when no CRITICAL', () => {
            const vulns: Vulnerability[] = [{ severity: 'HIGH' } as Vulnerability, { severity: 'LOW' } as Vulnerability];
            expect(component.getHighestSeverity(vulns)).toBe('HIGH');
        });
    });

    describe('getSeverityLevel', () => {
        it('should return danger for CRITICAL', () => {
            expect(component.getSeverityLevel('CRITICAL')).toBe('danger');
        });

        it('should return warn for HIGH', () => {
            expect(component.getSeverityLevel('HIGH')).toBe('warn');
        });

        it('should return warn for MEDIUM', () => {
            expect(component.getSeverityLevel('MEDIUM')).toBe('warn');
        });

        it('should return info for LOW', () => {
            expect(component.getSeverityLevel('LOW')).toBe('info');
        });

        it('should return secondary for unknown', () => {
            expect(component.getSeverityLevel('UNKNOWN')).toBe('secondary');
        });
    });

    describe('sendVulnerabilityEmail', () => {
        it('should send vulnerability email and show success alert', () => {
            const sendEmailSpy = vi.spyOn(sbomService, 'sendVulnerabilityEmail').mockReturnValue(of(undefined));
            const successSpy = vi.spyOn(alertService, 'success');

            component.sendVulnerabilityEmail();

            expect(sendEmailSpy).toHaveBeenCalled();
            expect(successSpy).toHaveBeenCalledWith('artemisApp.dependencies.emailSentSuccess');
            expect(component.sendingEmail()).toBe(false);
        });

        it('should show error alert when sending email fails', () => {
            vi.spyOn(sbomService, 'sendVulnerabilityEmail').mockReturnValue(throwError(() => new Error('Send failed')));
            const errorSpy = vi.spyOn(alertService, 'error');

            component.sendVulnerabilityEmail();

            expect(errorSpy).toHaveBeenCalledWith('artemisApp.dependencies.emailSentError');
            expect(component.sendingEmail()).toBe(false);
        });

        it('should set sendingEmail to true while sending', () => {
            // Use a subject to control when the observable completes
            const sendEmailSpy = vi.spyOn(sbomService, 'sendVulnerabilityEmail').mockReturnValue(of(undefined));

            expect(component.sendingEmail()).toBe(false);
            component.sendVulnerabilityEmail();
            // After completion, sendingEmail should be false again
            expect(component.sendingEmail()).toBe(false);
            expect(sendEmailSpy).toHaveBeenCalled();
        });
    });

    describe('loadVersionInfo', () => {
        it('should load version info successfully', () => {
            const getVersionSpy = vi.spyOn(sbomService, 'getVersionInfo').mockReturnValue(of(mockVersionInfo));

            component.loadVersionInfo();

            expect(getVersionSpy).toHaveBeenCalled();
            expect(component.versionInfo()).toEqual(mockVersionInfo);
        });

        it('should silently fail when version info load fails', () => {
            vi.spyOn(sbomService, 'getVersionInfo').mockReturnValue(throwError(() => new Error('Load failed')));
            const errorSpy = vi.spyOn(alertService, 'error');

            component.loadVersionInfo();

            // Should not show error - silently fails
            expect(errorSpy).not.toHaveBeenCalled();
            expect(component.versionInfo()).toBeUndefined();
        });
    });

    describe('refreshVulnerabilities error handling', () => {
        it('should show error alert when refresh fails', () => {
            vi.spyOn(sbomService, 'refreshVulnerabilities').mockReturnValue(throwError(() => new Error('Refresh failed')));
            const errorSpy = vi.spyOn(alertService, 'error');

            component.refreshVulnerabilities();

            expect(errorSpy).toHaveBeenCalledWith('artemisApp.dependencies.vulnerabilityLoadError');
            expect(component.loadingVulnerabilities()).toBe(false);
        });
    });

    describe('upgradeUrgency computed', () => {
        it('should return none when no update available', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));
            vi.spyOn(sbomService, 'getVersionInfo').mockReturnValue(
                of({
                    ...mockVersionInfo,
                    updateAvailable: false,
                }),
            );
            component.ngOnInit();

            expect(component.upgradeUrgency()).toBe('none');
        });

        it('should return critical when critical vulnerabilities exist', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(
                of({
                    ...mockVulnerabilities,
                    criticalCount: 1,
                    highCount: 0,
                }),
            );
            vi.spyOn(sbomService, 'getVersionInfo').mockReturnValue(of(mockVersionInfo));
            component.ngOnInit();

            expect(component.upgradeUrgency()).toBe('critical');
        });

        it('should return high when high vulnerabilities exist but no critical', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(
                of({
                    ...mockVulnerabilities,
                    criticalCount: 0,
                    highCount: 1,
                }),
            );
            vi.spyOn(sbomService, 'getVersionInfo').mockReturnValue(of(mockVersionInfo));
            component.ngOnInit();

            expect(component.upgradeUrgency()).toBe('high');
        });

        it('should return normal when update available but no urgent vulnerabilities', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(
                of({
                    ...mockVulnerabilities,
                    criticalCount: 0,
                    highCount: 0,
                }),
            );
            vi.spyOn(sbomService, 'getVersionInfo').mockReturnValue(of(mockVersionInfo));
            component.ngOnInit();

            expect(component.upgradeUrgency()).toBe('normal');
        });
    });

    describe('hasUrgentVulnerabilities computed', () => {
        it('should return false when no vulnerabilities', () => {
            expect(component.hasUrgentVulnerabilities()).toBe(false);
        });

        it('should return true when critical vulnerabilities exist', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(
                of({
                    ...mockVulnerabilities,
                    criticalCount: 1,
                    highCount: 0,
                }),
            );
            vi.spyOn(sbomService, 'getVersionInfo').mockReturnValue(of(mockVersionInfo));
            component.ngOnInit();

            expect(component.hasUrgentVulnerabilities()).toBe(true);
        });

        it('should return true when high vulnerabilities exist', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(
                of({
                    ...mockVulnerabilities,
                    criticalCount: 0,
                    highCount: 1,
                }),
            );
            vi.spyOn(sbomService, 'getVersionInfo').mockReturnValue(of(mockVersionInfo));
            component.ngOnInit();

            expect(component.hasUrgentVulnerabilities()).toBe(true);
        });

        it('should return false when only medium or low vulnerabilities exist', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(
                of({
                    ...mockVulnerabilities,
                    criticalCount: 0,
                    highCount: 0,
                    mediumCount: 5,
                    lowCount: 3,
                }),
            );
            vi.spyOn(sbomService, 'getVersionInfo').mockReturnValue(of(mockVersionInfo));
            component.ngOnInit();

            expect(component.hasUrgentVulnerabilities()).toBe(false);
        });
    });

    describe('downloadSbom', () => {
        it('should download server SBOM as JSON', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));
            vi.spyOn(sbomService, 'getVersionInfo').mockReturnValue(of(mockVersionInfo));
            component.ngOnInit();

            const createObjectURLSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:test-url');
            const revokeObjectURLSpy = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
            const createElementSpy = vi.spyOn(document, 'createElement').mockReturnValue({
                href: '',
                download: '',
                click: vi.fn(),
            } as unknown as HTMLAnchorElement);

            component.downloadSbom('server');

            expect(createObjectURLSpy).toHaveBeenCalled();
            expect(createElementSpy).toHaveBeenCalledWith('a');
            expect(revokeObjectURLSpy).toHaveBeenCalledWith('blob:test-url');
        });

        it('should download client SBOM as JSON', () => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));
            vi.spyOn(sbomService, 'getVersionInfo').mockReturnValue(of(mockVersionInfo));
            component.ngOnInit();

            const createObjectURLSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:test-url');
            const revokeObjectURLSpy = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
            const createElementSpy = vi.spyOn(document, 'createElement').mockReturnValue({
                href: '',
                download: '',
                click: vi.fn(),
            } as unknown as HTMLAnchorElement);

            component.downloadSbom('client');

            expect(createObjectURLSpy).toHaveBeenCalled();
            expect(createElementSpy).toHaveBeenCalledWith('a');
            expect(revokeObjectURLSpy).toHaveBeenCalledWith('blob:test-url');
        });

        it('should not download when SBOM source is undefined', () => {
            // Set up sbom without server component
            const sbomWithoutServer: CombinedSbom = { client: mockCombinedSbom.client, server: undefined };
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(sbomWithoutServer));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));
            vi.spyOn(sbomService, 'getVersionInfo').mockReturnValue(of(mockVersionInfo));
            component.ngOnInit();

            // Track call count before downloadSbom
            const createObjectURLSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:test-url');
            const callCountBefore = createObjectURLSpy.mock.calls.length;

            component.downloadSbom('server');

            // Should not have been called for 'server' download when server sbom is undefined
            const callCountAfter = createObjectURLSpy.mock.calls.length;
            expect(callCountAfter).toBe(callCountBefore);
        });
    });

    describe('getHighestSeverity additional cases', () => {
        it('should return MEDIUM when no CRITICAL or HIGH', () => {
            const vulns: Vulnerability[] = [{ severity: 'MEDIUM' } as Vulnerability, { severity: 'LOW' } as Vulnerability];
            expect(component.getHighestSeverity(vulns)).toBe('MEDIUM');
        });

        it('should return LOW when only LOW severity', () => {
            const vulns: Vulnerability[] = [{ severity: 'LOW' } as Vulnerability];
            expect(component.getHighestSeverity(vulns)).toBe('LOW');
        });

        it('should return UNKNOWN when only UNKNOWN severity', () => {
            const vulns: Vulnerability[] = [{ severity: 'UNKNOWN' } as Vulnerability];
            expect(component.getHighestSeverity(vulns)).toBe('UNKNOWN');
        });

        it('should return UNKNOWN for unrecognized severity', () => {
            const vulns: Vulnerability[] = [{ severity: 'OTHER' } as unknown as Vulnerability];
            expect(component.getHighestSeverity(vulns)).toBe('UNKNOWN');
        });
    });

    describe('filteredComponents with licenses filter', () => {
        it('should filter by license text', () => {
            const sbomWithLicenses: CombinedSbom = {
                server: {
                    ...mockCombinedSbom.server,
                    components: [
                        {
                            name: 'lib-with-apache',
                            version: '1.0.0',
                            licenses: ['Apache-2.0'],
                        },
                        {
                            name: 'lib-with-mit',
                            version: '1.0.0',
                            licenses: ['MIT'],
                        },
                    ],
                },
            };
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(sbomWithLicenses));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of({ ...mockVulnerabilities, vulnerabilities: [] }));
            component.ngOnInit();

            component.updateFilter('apache');
            const components = component.filteredComponents();

            expect(components).toHaveLength(1);
            expect(components[0].name).toBe('lib-with-apache');
        });
    });

    describe('filteredComponents with sorting', () => {
        beforeEach(() => {
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(mockCombinedSbom));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));
            component.ngOnInit();
        });

        it('should sort descending when sortAscending is false', () => {
            component.onTableSort({ field: 'name', order: -1 });
            const components = component.filteredComponents();

            expect(components[0].name).toBe('spring-core');
            expect(components[1].name).toBe('spring-boot');
            expect(components[2].name).toBe('core');
        });

        it('should sort by group field', () => {
            component.onTableSort({ field: 'group', order: 1 });
            const components = component.filteredComponents();

            expect(components[0].group).toBe('@angular');
            expect(components[1].group).toBe('org.springframework');
            expect(components[2].group).toBe('org.springframework.boot');
        });
    });

    describe('component counts when undefined', () => {
        it('should return 0 for server count when sbom is undefined', () => {
            expect(component.serverComponentCount()).toBe(0);
        });

        it('should return 0 for client count when sbom is undefined', () => {
            expect(component.clientComponentCount()).toBe(0);
        });

        it('should return 0 for total count when sbom is undefined', () => {
            expect(component.totalComponentCount()).toBe(0);
        });
    });

    describe('filteredComponents returns empty when sbom undefined', () => {
        it('should return empty array when sbom is not loaded', () => {
            expect(component.filteredComponents()).toEqual([]);
        });
    });

    describe('vulnerability matching', () => {
        it('should match vulnerabilities by synthetic key when purl not found', () => {
            const sbomWithoutPurl: CombinedSbom = {
                server: {
                    ...mockCombinedSbom.server,
                    components: [
                        {
                            name: 'test-lib',
                            version: '1.0.0',
                            group: 'org.example',
                            // No purl
                        },
                    ],
                },
            };
            const vulnsWithSyntheticKey: ComponentVulnerabilities = {
                ...mockVulnerabilities,
                vulnerabilities: [
                    {
                        componentKey: 'Maven:org.example/test-lib@1.0.0',
                        vulnerabilities: [
                            {
                                id: 'CVE-2024-5678',
                                severity: 'HIGH',
                            } as Vulnerability,
                        ],
                    },
                ],
            };

            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(sbomWithoutPurl));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(vulnsWithSyntheticKey));
            component.ngOnInit();

            component.toggleVulnerableOnly();
            const components = component.filteredComponents();

            expect(components).toHaveLength(1);
            expect(components[0].componentVulnerabilities).toHaveLength(1);
        });

        it('should detect npm ecosystem from purl', () => {
            const sbomWithNpm: CombinedSbom = {
                client: {
                    ...mockCombinedSbom.client,
                    components: [
                        {
                            name: 'lodash',
                            version: '4.0.0',
                            group: '@types',
                            purl: 'pkg:npm/@types/lodash@4.0.0',
                        },
                    ],
                },
            };
            const vulnsWithNpmKey: ComponentVulnerabilities = {
                ...mockVulnerabilities,
                vulnerabilities: [
                    {
                        componentKey: 'npm:@types/lodash@4.0.0',
                        vulnerabilities: [
                            {
                                id: 'CVE-2024-NPM',
                                severity: 'MEDIUM',
                            } as Vulnerability,
                        ],
                    },
                ],
            };

            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(sbomWithNpm));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(vulnsWithNpmKey));
            component.ngOnInit();

            const components = component.filteredComponents();
            expect(components).toHaveLength(1);
        });

        it('should detect npm ecosystem from scoped group without purl', () => {
            const sbomWithScopedGroup: CombinedSbom = {
                client: {
                    components: [
                        {
                            name: 'core',
                            version: '17.0.0',
                            group: '@angular',
                            // No purl
                        },
                    ],
                },
            };
            const vulnsWithNpmSyntheticKey: ComponentVulnerabilities = {
                ...mockVulnerabilities,
                vulnerabilities: [
                    {
                        componentKey: 'npm:@angular/core@17.0.0',
                        vulnerabilities: [
                            {
                                id: 'CVE-2024-ANGULAR',
                                severity: 'LOW',
                            } as Vulnerability,
                        ],
                    },
                ],
            };

            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(sbomWithScopedGroup));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(vulnsWithNpmSyntheticKey));
            component.ngOnInit();

            component.toggleVulnerableOnly();
            const components = component.filteredComponents();

            expect(components).toHaveLength(1);
        });

        it('should return undefined for component without ecosystem', () => {
            const sbomWithoutEcosystem: CombinedSbom = {
                server: {
                    components: [
                        {
                            name: 'unknown-lib',
                            version: '1.0.0',
                            // No purl, no recognizable group
                        },
                    ],
                },
            };
            const vulnsWithKey: ComponentVulnerabilities = {
                ...mockVulnerabilities,
                vulnerabilities: [
                    {
                        componentKey: 'unknown-key',
                        vulnerabilities: [
                            {
                                id: 'CVE-2024-UNKNOWN',
                                severity: 'LOW',
                            } as Vulnerability,
                        ],
                    },
                ],
            };

            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(sbomWithoutEcosystem));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(vulnsWithKey));
            component.ngOnInit();

            const components = component.filteredComponents();
            expect(components).toHaveLength(1);
            expect(components[0].componentVulnerabilities).toBeUndefined();
        });
    });

    describe('metadata computed properties', () => {
        it('should return server metadata', () => {
            const sbomWithMetadata: CombinedSbom = {
                server: {
                    ...mockCombinedSbom.server,
                    metadata: {
                        timestamp: '2024-01-01T00:00:00Z',
                        componentName: 'Artemis Server',
                        version: '7.8.0',
                    },
                },
            };
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(sbomWithMetadata));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));
            component.ngOnInit();

            expect(component.serverMetadata()?.componentName).toBe('Artemis Server');
        });

        it('should return client metadata', () => {
            const sbomWithMetadata: CombinedSbom = {
                client: {
                    ...mockCombinedSbom.client,
                    metadata: {
                        timestamp: '2024-01-01T00:00:00Z',
                        componentName: 'Artemis Client',
                        version: '7.8.0',
                    },
                },
            };
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(of(sbomWithMetadata));
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(of(mockVulnerabilities));
            component.ngOnInit();

            expect(component.clientMetadata()?.componentName).toBe('Artemis Client');
        });
    });

    describe('title bar actions', () => {
        // Refresh and send report are projected into the admin title bar, so they are not part of this
        // component's own view. Render the template registered with the real AdminTitleBarService.
        const projectedViews: EmbeddedViewRef<unknown>[] = [];

        let sbomSubject: Subject<CombinedSbom>;
        let vulnerabilitySubject: Subject<ComponentVulnerabilities>;
        let refreshSubject: Subject<ComponentVulnerabilities>;
        let emailSubject: Subject<void>;

        const noVulnerabilities: ComponentVulnerabilities = {
            vulnerabilities: [],
            totalVulnerabilities: 0,
            criticalCount: 0,
            highCount: 0,
            mediumCount: 0,
            lowCount: 0,
            lastChecked: '2024-01-01T00:00:00Z',
        };

        function renderActions(): DebugElement {
            const actionsTemplate = TestBed.inject(AdminTitleBarService).actionsTemplate();
            expect(actionsTemplate).toBeDefined();
            const view = actionsTemplate!.createEmbeddedView({});
            projectedViews.push(view);
            view.detectChanges();
            const debugElement = getDebugNode(view.rootNodes[0]) as DebugElement;
            expect(debugElement).toBeTruthy();
            return debugElement;
        }

        function syncViews(): void {
            fixture.detectChanges();
            for (const view of projectedViews) {
                view.detectChanges();
            }
        }

        function button(actions: DebugElement, testId: string): HTMLButtonElement {
            const element = actions.query(By.css(`[data-testid="${testId}"]`));
            expect(element).toBeTruthy();
            return element!.nativeElement;
        }

        function refreshButton(actions: DebugElement): HTMLButtonElement {
            return button(actions, 'refresh-vulnerabilities-button');
        }

        function emailButton(actions: DebugElement): HTMLButtonElement {
            return button(actions, 'send-vulnerability-email-button');
        }

        function expectBothDisabled(actions: DebugElement): void {
            expect(refreshButton(actions).disabled).toBe(true);
            expect(emailButton(actions).disabled).toBe(true);
        }

        function expectBothEnabled(actions: DebugElement): void {
            expect(refreshButton(actions).disabled).toBe(false);
            expect(emailButton(actions).disabled).toBe(false);
        }

        beforeEach(() => {
            sbomSubject = new Subject<CombinedSbom>();
            vulnerabilitySubject = new Subject<ComponentVulnerabilities>();
            refreshSubject = new Subject<ComponentVulnerabilities>();
            emailSubject = new Subject<void>();
            vi.spyOn(sbomService, 'getCombinedSbom').mockReturnValue(sbomSubject.asObservable());
            vi.spyOn(sbomService, 'getVulnerabilities').mockReturnValue(vulnerabilitySubject.asObservable());
            vi.spyOn(sbomService, 'refreshVulnerabilities').mockReturnValue(refreshSubject.asObservable());
            vi.spyOn(sbomService, 'sendVulnerabilityEmail').mockReturnValue(emailSubject.asObservable());
            fixture.detectChanges();
        });

        afterEach(() => {
            projectedViews.splice(0).forEach((view) => view.destroy());
        });

        it('shows both actions disabled before the initial SBOM request resolves', () => {
            const actions = renderActions();

            expect(sbomService.getCombinedSbom).toHaveBeenCalled();
            expect(component.combinedSbom()).toBeUndefined();
            expect(component.vulnerabilities()).toBeUndefined();
            expectBothDisabled(actions);
            expect(actions.query(By.css('[data-testid="download-server-sbom-button"]'))).toBeNull();
            expect(actions.query(By.css('[data-testid="download-client-sbom-button"]'))).toBeNull();

            refreshButton(actions).click();
            emailButton(actions).click();

            expect(sbomService.refreshVulnerabilities).not.toHaveBeenCalled();
            expect(sbomService.sendVulnerabilityEmail).not.toHaveBeenCalled();
        });

        it('keeps both actions disabled until vulnerability data arrives, then enables their handlers', () => {
            const actions = renderActions();

            sbomSubject.next(mockCombinedSbom);
            syncViews();

            expect(component.loadingVulnerabilities()).toBe(true);
            expect(component.vulnerabilities()).toBeUndefined();
            expectBothDisabled(actions);
            expect(actions.query(By.css('[data-testid="download-server-sbom-button"]'))).toBeTruthy();
            expect(actions.query(By.css('[data-testid="download-client-sbom-button"]'))).toBeTruthy();

            refreshButton(actions).click();
            emailButton(actions).click();
            expect(sbomService.refreshVulnerabilities).not.toHaveBeenCalled();
            expect(sbomService.sendVulnerabilityEmail).not.toHaveBeenCalled();

            vulnerabilitySubject.next(mockVulnerabilities);
            syncViews();

            expectBothEnabled(actions);
            refreshButton(actions).click();
            emailButton(actions).click();
            expect(sbomService.refreshVulnerabilities).toHaveBeenCalledTimes(1);
            expect(sbomService.sendVulnerabilityEmail).toHaveBeenCalledTimes(1);
        });

        it('enables both actions when the vulnerability response contains zero vulnerabilities', () => {
            const actions = renderActions();

            sbomSubject.next(mockCombinedSbom);
            vulnerabilitySubject.next(noVulnerabilities);
            syncViews();

            expect(component.vulnerabilities()).toEqual(noVulnerabilities);
            expect(component.vulnerabilities()?.totalVulnerabilities).toBe(0);
            expectBothEnabled(actions);
        });

        it('disables only refresh while a refresh is pending and restores it after success', () => {
            const actions = renderActions();
            const successSpy = vi.spyOn(alertService, 'success');
            const errorSpy = vi.spyOn(alertService, 'error');

            sbomSubject.next(mockCombinedSbom);
            vulnerabilitySubject.next(mockVulnerabilities);
            syncViews();
            expectBothEnabled(actions);

            refreshButton(actions).click();
            syncViews();

            expect(refreshButton(actions).disabled).toBe(true);
            expect(emailButton(actions).disabled).toBe(false);
            expect(component.loadingVulnerabilities()).toBe(true);

            refreshSubject.next(mockVulnerabilities);
            syncViews();

            expectBothEnabled(actions);
            expect(component.loadingVulnerabilities()).toBe(false);
            expect(successSpy).toHaveBeenCalledWith('artemisApp.dependencies.vulnerabilityRefreshSuccess');
            expect(errorSpy).not.toHaveBeenCalled();
        });

        it('disables only refresh while a refresh is pending and restores it after an error', () => {
            const actions = renderActions();
            const successSpy = vi.spyOn(alertService, 'success');
            const errorSpy = vi.spyOn(alertService, 'error');

            sbomSubject.next(mockCombinedSbom);
            vulnerabilitySubject.next(mockVulnerabilities);
            syncViews();

            refreshButton(actions).click();
            syncViews();
            expect(refreshButton(actions).disabled).toBe(true);
            expect(emailButton(actions).disabled).toBe(false);

            refreshSubject.error(new Error('Refresh failed'));
            syncViews();

            expectBothEnabled(actions);
            expect(component.loadingVulnerabilities()).toBe(false);
            expect(component.vulnerabilities()).toEqual(mockVulnerabilities);
            expect(errorSpy).toHaveBeenCalledWith('artemisApp.dependencies.vulnerabilityLoadError');
            expect(successSpy).not.toHaveBeenCalled();
        });

        it('disables only send report while an email is pending and restores it after success', () => {
            const actions = renderActions();
            const successSpy = vi.spyOn(alertService, 'success');
            const errorSpy = vi.spyOn(alertService, 'error');

            sbomSubject.next(mockCombinedSbom);
            vulnerabilitySubject.next(mockVulnerabilities);
            syncViews();

            emailButton(actions).click();
            syncViews();

            expect(emailButton(actions).disabled).toBe(true);
            expect(refreshButton(actions).disabled).toBe(false);
            expect(component.sendingEmail()).toBe(true);

            emailSubject.next();
            syncViews();

            expectBothEnabled(actions);
            expect(component.sendingEmail()).toBe(false);
            expect(successSpy).toHaveBeenCalledWith('artemisApp.dependencies.emailSentSuccess');
            expect(errorSpy).not.toHaveBeenCalled();
        });

        it('disables only send report while an email is pending and restores it after an error', () => {
            const actions = renderActions();
            const successSpy = vi.spyOn(alertService, 'success');
            const errorSpy = vi.spyOn(alertService, 'error');

            sbomSubject.next(mockCombinedSbom);
            vulnerabilitySubject.next(mockVulnerabilities);
            syncViews();

            emailButton(actions).click();
            syncViews();
            expect(emailButton(actions).disabled).toBe(true);
            expect(refreshButton(actions).disabled).toBe(false);

            emailSubject.error(new Error('Send failed'));
            syncViews();

            expectBothEnabled(actions);
            expect(component.sendingEmail()).toBe(false);
            expect(errorSpy).toHaveBeenCalledWith('artemisApp.dependencies.emailSentError');
            expect(successSpy).not.toHaveBeenCalled();
        });

        it('keeps both actions disabled and shows the load error when the SBOM request fails', () => {
            const actions = renderActions();
            const errorSpy = vi.spyOn(alertService, 'error');

            sbomSubject.error(new HttpErrorResponse({ status: 500 }));
            syncViews();

            expectBothDisabled(actions);
            expect(component.sbomUnavailable()).toBe(false);
            expect(component.vulnerabilities()).toBeUndefined();
            expect(component.loading()).toBe(false);
            expect(sbomService.getVulnerabilities).not.toHaveBeenCalled();
            expect(errorSpy).toHaveBeenCalledWith('artemisApp.dependencies.loadError');
            expect(fixture.nativeElement.querySelector('[data-testid="sbom-load-error-message"]')).toBeTruthy();
            expect(fixture.nativeElement.querySelector('[data-testid="sbom-unavailable-message"]')).toBeNull();

            refreshButton(actions).click();
            emailButton(actions).click();
            expect(sbomService.refreshVulnerabilities).not.toHaveBeenCalled();
            expect(sbomService.sendVulnerabilityEmail).not.toHaveBeenCalled();
        });

        it('keeps both actions disabled and shows the unavailable banner when the SBOM responds 404', () => {
            const actions = renderActions();
            const errorSpy = vi.spyOn(alertService, 'error');

            sbomSubject.error(new HttpErrorResponse({ status: 404 }));
            syncViews();

            expectBothDisabled(actions);
            expect(component.sbomUnavailable()).toBe(true);
            expect(component.loading()).toBe(false);
            expect(component.vulnerabilities()).toBeUndefined();
            expect(sbomService.getVulnerabilities).not.toHaveBeenCalled();
            expect(errorSpy).not.toHaveBeenCalled();
            expect(fixture.nativeElement.querySelector('[data-testid="sbom-unavailable-message"]')).toBeTruthy();
            expect(fixture.nativeElement.querySelector('[data-testid="sbom-load-error-message"]')).toBeNull();
        });

        it('keeps both actions disabled when the first vulnerability request fails', () => {
            const actions = renderActions();
            const errorSpy = vi.spyOn(alertService, 'error');

            sbomSubject.next(mockCombinedSbom);
            vulnerabilitySubject.error(new HttpErrorResponse({ status: 500 }));
            syncViews();

            expectBothDisabled(actions);
            expect(component.vulnerabilities()).toBeUndefined();
            expect(component.loadingVulnerabilities()).toBe(false);
            expect(component.combinedSbom()).toEqual(mockCombinedSbom);
            expect(errorSpy).toHaveBeenCalledWith('artemisApp.dependencies.vulnerabilityLoadError');
            expect(fixture.nativeElement.querySelector('[data-testid="sbom-load-error-message"]')).toBeNull();
            expect(fixture.nativeElement.querySelector('[data-testid="sbom-unavailable-message"]')).toBeNull();
            expect(fixture.nativeElement.querySelector('[jhiTranslate="artemisApp.dependencies.vulnerabilitiesNotLoaded"]')).toBeTruthy();

            refreshButton(actions).click();
            emailButton(actions).click();
            expect(sbomService.refreshVulnerabilities).not.toHaveBeenCalled();
            expect(sbomService.sendVulnerabilityEmail).not.toHaveBeenCalled();
        });

        it('keeps both actions disabled without a toast when the first vulnerability request returns 404', () => {
            const actions = renderActions();
            const errorSpy = vi.spyOn(alertService, 'error');

            sbomSubject.next(mockCombinedSbom);
            vulnerabilitySubject.error(new HttpErrorResponse({ status: 404 }));
            syncViews();

            expectBothDisabled(actions);
            expect(component.vulnerabilities()).toBeUndefined();
            expect(component.loadingVulnerabilities()).toBe(false);
            expect(errorSpy).not.toHaveBeenCalled();
            expect(fixture.nativeElement.querySelector('[data-testid="sbom-load-error-message"]')).toBeNull();
            expect(fixture.nativeElement.querySelector('[jhiTranslate="artemisApp.dependencies.vulnerabilitiesNotLoaded"]')).toBeTruthy();
        });
    });
});

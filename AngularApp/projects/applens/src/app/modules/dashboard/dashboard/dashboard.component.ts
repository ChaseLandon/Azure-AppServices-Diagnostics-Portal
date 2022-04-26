import { AdalService } from 'adal-angular4';
import { Subscription, Observable } from 'rxjs';
import { Component, OnDestroy, OnInit, Pipe, PipeTransform } from '@angular/core';
import { ResourceService } from '../../../shared/services/resource.service';
import * as momentNs from 'moment';
import { DetectorControlService, FeatureNavigationService, DetectorMetaData, DetectorType, BreadcrumbNavigationItem } from 'diagnostic-data';
import { ApplensDiagnosticService } from '../services/applens-diagnostic.service';
import { Router, ActivatedRoute, NavigationExtras, NavigationEnd, Params } from '@angular/router';
import { SearchService } from '../services/search.service';
import { environment } from '../../../../environments/environment';
import { DiagnosticApiService } from '../../../shared/services/diagnostic-api.service';
import { ObserverService } from '../../../shared/services/observer.service';
import { ICommandBarProps, PanelType, IBreadcrumbProps, IBreadcrumbItem, ITooltipHostProps, SpinnerSize, DialogType } from 'office-ui-fabric-react';
import { ApplensGlobal } from '../../../applens-global';
import { L2SideNavType } from '../l2-side-nav/l2-side-nav';
import { l1SideNavCollapseWidth, l1SideNavExpandWidth } from '../../../shared/components/l1-side-nav/l1-side-nav';
import { filter } from 'rxjs/operators';
import { StartupService } from '../../../shared/services/startup.service';
import { UserInfo } from '../user-detectors/user-detectors.component';
import { BreadcrumbService } from '../services/breadcrumb.service';
import {AlertService} from '../../../shared/services/alert.service';
import {AlertInfo, ConfirmationOption} from '../../../shared/models/alerts';
import { TelemetryService } from '../../../../../../diagnostic-data/src/lib/services/telemetry/telemetry.service';
import { TelemetryEventNames } from '../../../../../../diagnostic-data/src/lib/services/telemetry/telemetry.common';

@Component({
  selector: 'dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnDestroy {
  startTime: momentNs.Moment;
  endTime: momentNs.Moment;

  contentHeight: string;

  navigateSub: Subscription;
  userId: string = "";
  userName: string = "";
  displayName: string = "";
  userPhotoSource: string = undefined;
  keys: string[];
  currentRoutePath: string[];
  resource: any;
  observerLink: string = "";
  showUserInformation: boolean;
  resourceReady: Observable<any>;
  resourceDetailsSub: Subscription;
  type: PanelType = PanelType.custom;
  width: string = "850px";
  showTitle: boolean = true;
  panelStyles: any = {
    root: {
      marginTop: '50px',
    }
  }

  commandBarStyles: ICommandBarProps["styles"] = {
    root: {
      padding: "0px"
    }
  };

  title: string = "";
  showL2SideNav: boolean = false;
  expandL1SideNav: boolean = false;
  breadcrumbItems: IBreadcrumbItem[] = [];
  breadcrumbStyles: IBreadcrumbProps['styles'] = {
    itemLink: {
      fontSize:"14px",
    },
  }
  breadcrumbTooltipHostProps: IBreadcrumbProps['tooltipHostProps'] = {
    styles: {
      root: {
        fontWeight: "400",
        color: "#256ccf",
      }
    }
  }

  accessError: string = '';
  displayAlertDialog: boolean = false;
  displayErrorInDialog: boolean = false;
  errorInDialog: string = null;
  showLoaderInDialog: boolean = false;
  alertInfo: AlertInfo = null;
  stillLoading: boolean = false;
  loaderSize = SpinnerSize.large;
  showDashboardContent: boolean = true;
  alertDialogStyles = { main: { maxWidth: "70vw!important", minWidth: "40vw!important" } };
  alertDialogProps = {isBlocking: true}
  dialogType: DialogType = DialogType.normal;

  constructor(public resourceService: ResourceService, private startupService: StartupService,  private _detectorControlService: DetectorControlService,
    private _router: Router, private _activatedRoute: ActivatedRoute, private _navigator: FeatureNavigationService,
    private _diagnosticService: ApplensDiagnosticService, private _adalService: AdalService, public _searchService: SearchService,
    private _diagnosticApiService: DiagnosticApiService, private _observerService: ObserverService, public _applensGlobal: ApplensGlobal,
    private _startupService: StartupService, private _resourceService: ResourceService, private _breadcrumbService: BreadcrumbService,
    private _alertService: AlertService, private _telemetryService: TelemetryService) {
    this.contentHeight = (window.innerHeight - 50) + 'px';

    this.navigateSub = this._navigator.OnDetectorNavigate.subscribe((detector: string) => {
      if (detector) {
        this._router.navigate([`./detectors/${detector}`], { relativeTo: this._activatedRoute, queryParamsHandling: 'merge' });

        this._diagnosticService.getDetectors().subscribe(detectors => {
          // this.detectors = detectors;
          // let detectorMetaData: DetectorMetaData = detectors.find(d => d.id.toLowerCase() === detector.toLowerCase());
          // if (detectorMetaData) {
          //   if (detectorMetaData.type === DetectorType.Detector) {
          //     this._router.navigate([`./detectors/${detector}`], { relativeTo: this._activatedRoute, queryParamsHandling: 'merge' });
          //   } else if (detectorMetaData.type === DetectorType.Analysis) {
          //     this._router.navigate([`./analysis/${detector}`], { relativeTo: this._activatedRoute, queryParamsHandling: 'merge' });
          //   }
          // }
        },
        (err) => {
          let errobj = JSON.parse(err.error);
          this.accessError = errobj.DetailText;
          if (!this.CheckIsResourceUnrelatedError(errobj.DetailText)){ this.navigateBackToHomePage(); }
        });
      }
    });

    // Add time params to route if not already present
    if (!this._activatedRoute.queryParams['startTime'] || !this._activatedRoute.queryParams['endTime']) {
      let routeParams = {
        'startTime': this._detectorControlService.startTime.format('YYYY-MM-DDTHH:mm'),
        'endTime': this._detectorControlService.endTime.format('YYYY-MM-DDTHH:mm')
      }
      // If browser URL contains detectorQueryParams, adding it to route
      if (!this._activatedRoute.queryParams['detectorQueryParams']) {
        routeParams['detectorQueryParams'] = this._activatedRoute.snapshot.queryParams['detectorQueryParams'];
      }
      if (!this._activatedRoute.queryParams['searchTerm']) {
        this._searchService.searchTerm = this._activatedRoute.snapshot.queryParams['searchTerm'];
        routeParams['searchTerm'] = this._activatedRoute.snapshot.queryParams['searchTerm'];
      }
      if (!this._activatedRoute.queryParams['caseNumber']) {
        this._diagnosticApiService.setCustomerCaseNumber(this._activatedRoute.snapshot.queryParams['caseNumber']);
        routeParams['caseNumber'] = this._activatedRoute.snapshot.queryParams['caseNumber'];
      }

      this._router.navigate([], { queryParams: routeParams, queryParamsHandling: 'merge', relativeTo: this._activatedRoute });
    }

    if ((this.showUserInformation = environment.adal.enabled)) {
      let alias = this._adalService.userInfo.profile ? this._adalService.userInfo.profile.upn : '';
      this.userId = alias.replace('@microsoft.com', '');
      this._diagnosticService.getUserPhoto(this.userId).subscribe(image => {
        this.userPhotoSource = image;
      });

      this._diagnosticService.getUserInfo(this.userId).subscribe((userInfo: UserInfo) => {
        this.userName = userInfo.givenName;
        this.displayName = userInfo.displayName;
      });
    }

    this._alertService.getAlert().subscribe((alert: AlertInfo) => {
      this.alertInfo = alert;
      this.displayAlertDialog = true;
      setTimeout(() => {
        var elem = document.getElementsByClassName('ms-Dialog-title')[0] as HTMLElement;
        if (elem) {
          elem.focus();
        }
      }, 500);
    });
  }

  resetDialogSuccessStatus(){
    this.errorInDialog = null;
    this.displayErrorInDialog = false;
  }

  CheckIsResourceUnrelatedError(detailText){
    return detailText && detailText.includes("resource is not related to the case");
  }

  handleUserResponse(userResponse: ConfirmationOption) {
    let alias = this._adalService.userInfo.profile ? this._adalService.userInfo.profile.upn : '';
    this._telemetryService.logEvent(TelemetryEventNames.ResourceOutOfScopeUserResponse, {userId: alias, url: this._router.url, userResponse: userResponse.label, caseNumber: this._diagnosticApiService.CustomerCaseNumber});
    if (userResponse.value === 'yes') {
      this.showLoaderInDialog = true;
      this._diagnosticService.unrelatedResourceConfirmation().subscribe(() => {
        this.showLoaderInDialog = false;
        this.displayAlertDialog = false;
        this.alertInfo = null;
        location.reload();
      },
      (err) => {
        this.showLoaderInDialog = false;
        let error = err.message;
        this.errorInDialog = error;
        this.displayErrorInDialog = true;
      });
    }
    else if (userResponse.value == 'no') {
      this.accessError = this.alertInfo.details;
      this.navigateBackToHomePage();
    }
  }

  navigateBackToHomePage() {
    let resourceInfo = this._startupService.getResourceInfo();
    let queryParams = {
      caseNumber: this._diagnosticApiService.CustomerCaseNumber,
      errorMessage: this.accessError,
      resourceType: `${resourceInfo.provider}/${resourceInfo.resourceTypeName}`,
      resourceName: resourceInfo.resourceName,
      resourceId: this._resourceService.getCurrentResourceId()
    };
    const queryString = new URLSearchParams(queryParams).toString();
    window.location.href = "/?" + queryString;
  }

  ngOnInit() {
    this.stillLoading = true;
    this._diagnosticService.getDetectors().subscribe(detectors => {
      this.stillLoading = false;
    },
    (err) => {
      this.stillLoading = false;
      this.showDashboardContent = false;
      let errobj = JSON.parse(err.error);
      this.accessError = errobj.DetailText;
      if (!this.CheckIsResourceUnrelatedError(errobj.DetailText))
      {
        this.navigateBackToHomePage();
      }
    });
    this.title="";
    this._applensGlobal.headerTitleSubject.subscribe(title => {
      this.title = title;
    });

    this._applensGlobal.openL2SideNavSubject.subscribe(type => {
      this.showL2SideNav = type !== L2SideNavType.None;
    });

    this._applensGlobal.expandL1SideNavSubject.subscribe(isExpand => {
      this.expandL1SideNav = isExpand;
    });

    if (!!this._activatedRoute && !!this._activatedRoute.snapshot && !!this._activatedRoute.snapshot.queryParams && !!this._activatedRoute.snapshot.queryParams['l']) {
      this._diagnosticApiService.effectiveLocale = this._activatedRoute.snapshot.queryParams['l'].toString().toLowerCase();
    }

    let serviceInputs = this._startupService.getInputs();
    this.resourceReady = this.resourceService.getCurrentResource();
    this.resourceReady.subscribe(resource => {
      if (resource) {
        this.resource = resource;
        if (serviceInputs.resourceType.toString().toLowerCase() === 'microsoft.web/hostingenvironments' && this.resource && this.resource.Name)
        {
            this.observerLink = "https://wawsobserver.azurewebsites.windows.net/MiniEnvironments/"+ this.resource.Name;
            this._diagnosticApiService.GeomasterServiceAddress = this.resource["GeomasterServiceAddress"];
            this._diagnosticApiService.GeomasterName = this.resource["GeomasterName"];
        }
        else if (serviceInputs.resourceType.toString().toLowerCase() === 'microsoft.web/sites')
        {
            this._diagnosticApiService.GeomasterServiceAddress = this.resource["GeomasterServiceAddress"];
            this._diagnosticApiService.GeomasterName = this.resource["GeomasterName"];
            this._diagnosticApiService.Location = this.resource["WebSpace"];
            this.observerLink = "https://wawsobserver.azurewebsites.windows.net/sites/"+ this.resource.SiteName;

            if (resource['IsXenon']) {
                this.resourceService.imgSrc = this.resourceService.altIcons['Xenon'];
            }
        }
        else if (serviceInputs.resourceType.toString().toLowerCase() === 'microsoft.web/containerapps' ||
                 serviceInputs.resourceType.toString().toLowerCase() === 'microsoft.app/containerapps')
        {
          this._diagnosticApiService.GeomasterServiceAddress = this.resource.ServiceAddress;
          this._diagnosticApiService.GeomasterName = this.resource.GeoMasterName;
          this.observerLink = "https://wawsobserver.azurewebsites.windows.net/partner/containerapp/" + this.resource.ContainerAppName;
        }

        this.keys = Object.keys(this.resource);
        this.replaceResourceEmptyValue();
        this.updateVentAndLinuxInfo();
      }
    });

    this._breadcrumbService.breadcrumbSubject.subscribe(items => {
      this.breadcrumbItems = [];
      items.forEach(i => {
        const breadcrumbItem = this.convertToBreadCrumbItem(i);
        this.breadcrumbItems.push(breadcrumbItem);
      });
      this.breadcrumbItems[this.breadcrumbItems.length - 1].isCurrentItem = true;
    });
  }


  triggerSearch() {
    this._searchService.searchTerm = this._searchService.searchTerm.trim();
    if (this._searchService.searchIsEnabled && this._searchService.searchTerm && this._searchService.searchTerm.length > 3) {
      this.navigateTo(`search`, { searchTerm: this._searchService.searchTerm }, 'merge');
    }
  }

  navigateTo(path: string, queryParams?: any, queryParamsHandling?: any) {
    let navigationExtras: NavigationExtras = {
      queryParamsHandling: queryParamsHandling || 'preserve',
      preserveFragment: true,
      relativeTo: this._activatedRoute,
      queryParams: queryParams
    };

    this._router.navigate([path], navigationExtras);
  }

  doesMatchCurrentRoute(expectedRoute: string) {
    return this.currentRoutePath && this.currentRoutePath.join('/') === expectedRoute;
  }

  navigateToUserPage() {
    this.navigateTo(`users/${this.userId}`);
  }

  dismissedHandler() {
    this._applensGlobal.openResourceInfoPanel = false;
 }

  copyToClipboard(item, event) {
    let listener = (e: ClipboardEvent) => {
      e.clipboardData.setData('text/plain', (item));
      e.preventDefault();
    };

    document.addEventListener('copy', listener);
    document.execCommand('copy');
    document.removeEventListener('copy', listener);

    event.target.src = "/assets/img/copy-icon-copied.png";
    setTimeout(() => {
      event.target.src = "/assets/img/copy-icon.png";
    }, 3000);
  }

  updateVentAndLinuxInfo() {
    if (this.keys.indexOf('VnetName') == -1 && this.resourceReady != null && this.resourceDetailsSub == null) {
      this.resourceDetailsSub = this.resourceReady.subscribe(resource => {
        if (resource) {
          this._observerService.getSiteRequestDetails(this.resource.SiteName, this.resource.InternalStampName).subscribe(siteInfo => {
            this.resource['VnetName'] = siteInfo.details.vnetname;
            this.keys.push('VnetName');

            if (this.resource['IsLinux']) {
              this.resource['LinuxFxVersion'] = siteInfo.details.linuxfxversion;
              this.keys.push('LinuxFxVersion');
            }

            this.replaceResourceEmptyValue();
          });
        }
      });
    }
  }

  replaceResourceEmptyValue() {
    this.keys.forEach(key => {
      if (this.resource[key] === "") {
        this.resource[key] = "N/A";
      }
    });
  }

  ngOnDestroy() {
    this.navigateSub.unsubscribe();
  }

  getContainerStyle() {
    const left = `${this.expandL1SideNav ? l1SideNavExpandWidth : l1SideNavCollapseWidth}px`;
    const width = `calc(100% - ${left})`;

    return {
      'left': left,
      'width': width
    }
  }

  private updateShowTitle() {
    const showTitle = this._activatedRoute.firstChild.snapshot.data["showTitle"];
    this.showTitle = showTitle === undefined ? true : showTitle;
  }

  private convertToBreadCrumbItem(navigationItem: BreadcrumbNavigationItem): IBreadcrumbItem {
    const item: IBreadcrumbItem = {
      key: navigationItem.name,
      text: navigationItem.name,
      onClick: (ev, item) => {
        this._breadcrumbService.navigate(navigationItem);
      }
    }
    return item;
  }
}

@Pipe({ name: 'formatResourceName' })
export class FormatResourceNamePipe implements PipeTransform {
  transform(resourceName: string): string {
    let displayedResourceName = resourceName;
    if (resourceName && resourceName.length >= 35) {
      displayedResourceName = resourceName.substring(0, 35).concat("...");
    }

    return displayedResourceName;
  }
}

import { Injectable } from "@angular/core";
import { AdalService } from "adal-angular4";
import { flatMap, map } from "rxjs/operators";
import { BehaviorSubject, Observable, of, throwError } from "rxjs";
import { FavoriteDetectorProp, FavoriteDetectors, LandingInfo, RecentResource, UserPanelSetting, UserSetting, } from "../../../shared/models/user-setting";
import { DiagnosticApiService } from "../../../shared/services/diagnostic-api.service";
import { HttpClient } from "@angular/common/http";

@Injectable()
export class UserSettingService {
    private _userSettingSubject: BehaviorSubject<UserSetting> = new BehaviorSubject(null);
    currentTheme: string = "light";
    currentViewMode: string = "smarter";
    currentThemeSub: BehaviorSubject<string> = new BehaviorSubject<string>("light");
    currentViewModeSub: BehaviorSubject<string> = new BehaviorSubject<string>("smarter");
    isWaterfallViewSub: BehaviorSubject<boolean> = new BehaviorSubject<boolean>(false);
    private set _userSetting(userSetting: UserSetting) {
        this._userSettingSubject.next(userSetting);
    }
    private get _userSetting() {
        return this._userSettingSubject.getValue();
    }

    private get _userId() {
        const alias = !!this._adalService.userInfo.profile && !!this._adalService.userInfo.profile.upn ? this._adalService.userInfo.profile.upn : '';
        return alias.replace('@microsoft.com', '');
    }

    private readonly maxRecentResources = 5;
    private readonly maxFavoriteDetectors = 5;
    readonly overMaxFavoriteDetectorError = `Over ${this.maxFavoriteDetectors} of Pinned detectors, Please remove some your pinned favorite detector`;

    constructor(private _diagnosticApiService: DiagnosticApiService, private _adalService: AdalService, private _httpClient: HttpClient) { 
    }

    getUserSetting(invalidateCache = false): Observable<UserSetting> {
        if (!!this._userSetting && !invalidateCache) {
            return this._userSettingSubject;
        }

        return this._diagnosticApiService.get<UserSetting>(`api/usersetting/${this._userId}`, invalidateCache).pipe(
            map(userSetting => {
                this._userSetting = userSetting;
                return userSetting;
            })
        );
    }

    getExpandAnalysisCheckCard() {
        return this.getUserSetting().pipe(map(userSetting => userSetting.expandAnalysisCheckCard));
    }

    isWaterfallViewMode() {
        return this.getUserSetting().pipe(map(userSetting => { return userSetting.viewMode == "waterfall" }));
    }


    updateThemeAndView(updatedUserSetting: UserSetting) {
        this.currentTheme = updatedUserSetting.theme;
        this.currentThemeSub.next(this.currentTheme);
        this.currentViewMode = updatedUserSetting.viewMode;
        this.currentViewModeSub.next(this.currentViewMode);
    }

    updateDefaultServiceType(serviceType: string) {
        if (this._userSetting) {
            this._userSetting.defaultServiceType = serviceType;
        }
    }

    private addRecentResource(newResource: RecentResource, userSetting: UserSetting): RecentResource[] {
        const res = [...this._userSetting.resources];
        const index = userSetting.resources.findIndex(resource => resource.resourceUri.toLowerCase() === newResource.resourceUri.toLowerCase());
        if (index >= 0) {
            res.splice(index, 1);
        } else if (res.length >= this.maxRecentResources) {
            res.pop();
        }
        res.unshift(newResource);

        return res;
    }

    updateUserPanelSetting(panelSettings: UserPanelSetting): Observable<UserSetting> {
        const url: string = `${this._diagnosticApiService.diagnosticApi}api/usersetting/${this._userId}/userPanelSetting`;
        return this._httpClient.post<UserSetting>(url, panelSettings).map(userSetting => this._userSetting = userSetting);
    }

    updateLandingInfo(resource: RecentResource): Observable<UserSetting> {
        const url: string = `${this._diagnosticApiService.diagnosticApi}api/usersetting/${this._userId}/landingInfo`;
        const updatedResources = this.addRecentResource(resource, this._userSetting);
        const info: LandingInfo = {
            resources: updatedResources,
            defaultServiceType: this._userSetting.defaultServiceType
        };
        return this._httpClient.post<UserSetting>(url, info).map(userSetting => {
            this._userSetting = userSetting;
            return userSetting;
        });
    }

    removeFavoriteDetector(detectorId: string): Observable<FavoriteDetectors> {
        const url = `${this._diagnosticApiService.diagnosticApi}api/usersetting/${this._userId}/favoriteDetectors/${detectorId}`;

        return this._httpClient.delete<UserSetting>(url).map(userSetting => {
            this._userSetting = userSetting;
            return userSetting.favoriteDetectors;
        });
    }

    addFavoriteDetector(detectorId: string, detectorProp: FavoriteDetectorProp): Observable<FavoriteDetectors> {
        if (Object.keys(this._userSetting.favoriteDetectors).length >= this.maxFavoriteDetectors) {
            return throwError(this.overMaxFavoriteDetectorError);
        }
        const url = `${this._diagnosticApiService.diagnosticApi}api/usersetting/${this._userId}/favoriteDetectors/${detectorId}`;
        return this._httpClient.post<UserSetting>(url, detectorProp).map(userSetting => {
            this._userSetting = userSetting;
            return userSetting.favoriteDetectors;
        });
    }
}

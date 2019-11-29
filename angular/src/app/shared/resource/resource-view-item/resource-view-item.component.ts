import { Component, Input } from '@angular/core';
import { FormControl, Validators } from '@angular/forms';
import { EntityModel } from 'ddap-common-lib';
import _get from 'lodash.get';
import { Subscription } from 'rxjs';

import { environment } from '../../../../environments/environment';
import { dam } from '../../proto/dam-service';
import { ResourceService } from '../resource.service';
import ResourceToken = dam.v1.ResourceTokens.ResourceToken;

@Component({
  selector: 'ddap-resource-view-item',
  templateUrl: './resource-view-item.component.html',
  styleUrls: ['./resource-view-item.component.scss'],
})
export class ResourceViewItemComponent {

  @Input()
  resource: EntityModel;
  @Input()
  view: EntityModel;
  @Input()
  damId: string;

  accessSubscription: Subscription;
  access: ResourceToken;
  url?: string;

  ttlForm = new FormControl(1, Validators.compose([Validators.required, Validators.min(1)]));
  selectedTimeUnit = 'h';
  // Downloads the same zip file regardless of realm
  downloadCliUrl = `${environment.ddapApiUrl}/master/cli/download`;

  constructor(private resourceService: ResourceService) {

  }

  getAccess(): void {
    const token = _get(this.access, 'token');
    if (token || !this.ttlForm.valid) {
      return;
    }

    const viewName = this.view.name;
    const ttl = `${this.ttlForm.value}${this.selectedTimeUnit}`;
    this.accessSubscription = this.resourceService
      .getAccessRequestToken(this.damId, this.resource.name, viewName, { ttl })
      .subscribe((access) => {
        this.access = access;
        this.url = this.getUrlIfApplicable(viewName, access.token);
        this.ttlForm.disable();
        this.accessSubscription.unsubscribe();
      });
  }

  getUrlIfApplicable(viewName: string, token: string): string {
    const view = this.resource.dto.views[viewName];
    const interfaces = view.interfaces;
    const httpInterfaces = Object.keys(interfaces)
      .filter((viewInterface) => viewInterface.startsWith('http'));

    if (!httpInterfaces.length) {
      return;
    }

    const viewAccessUrl = _get(interfaces, `[${httpInterfaces[0]}].uri[0]`);
    return `${viewAccessUrl}/o?access_token=${token}`;
  }

}

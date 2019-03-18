import { Component } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

import { ClientService } from '../clients.service';

@Component({
  selector: 'ddap-client-manage',
  templateUrl: './client-manage.component.html',
  styleUrls: ['./client-manage.component.scss'],
})
export class ClientManageComponent {

  constructor(private clientService: ClientService,
              private router: Router,
              private route: ActivatedRoute) {
  }

  save(id, change) {
    this.clientService.save(id, change)
      .subscribe(() => this.router.navigate(['../..'], { relativeTo: this.route }));
  }
}
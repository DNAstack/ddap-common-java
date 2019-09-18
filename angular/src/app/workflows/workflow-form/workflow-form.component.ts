import { Component, Input, OnChanges, OnInit, SimpleChanges, ViewEncapsulation } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { NoneComponent } from 'angular7-json-schema-form';
import _set from 'lodash.set';

import Form from '../../admin/shared/form/form';
import { SimplifiedWesResourceViews } from '../workflow.model';
import { WorkflowService } from '../workflows.service';

import { AutocompleteInputComponent } from './widget/autocomplete-input.component';

@Component({
  selector: 'ddap-workflow-form',
  templateUrl: './workflow-form.component.html',
  styleUrls: ['./workflow-form.component.scss'],
  encapsulation: ViewEncapsulation.None,
  entryComponents: [AutocompleteInputComponent],
})
export class WorkflowFormComponent implements Form, OnInit, OnChanges {

  @Input()
  datasetColumns: string[] = [];

  form: FormGroup;
  wesResourceViews: SimplifiedWesResourceViews[];
  inputSchema;
  widgets = {
    text: AutocompleteInputComponent,
    submit: NoneComponent,
  };
  options = {
    defautWidgetOptions: {
      typeahead: {
        source: [],
      },
    },
  };

  constructor(private formBuilder: FormBuilder,
              private workflowService: WorkflowService) {
  }

  ngOnInit(): void {
    this.form = this.formBuilder.group({
      wesView: ['', [Validators.required]],
      wdl: ['', [Validators.required]],
      inputs: ['', [Validators.required]],
    });

    this.workflowService.getAllWesViews()
      .subscribe((sanitizedWesResourceViews: SimplifiedWesResourceViews[]) => {
        this.wesResourceViews = sanitizedWesResourceViews;
      });
  }

  ngOnChanges(changes: SimpleChanges): void {
    _set(this.options, 'defautWidgetOptions.typeahead.source', changes.datasetColumns.currentValue);
  }

  getAllForms(): FormGroup[] {
    return [this.form];
  }

  isValid(): boolean {
    return this.form.valid;
  }

  getDamId(): string {
    return this.wesResourceViews.find((wesResourceViews: SimplifiedWesResourceViews) => {
      return wesResourceViews.views.some((view) => view.name === this.form.get('wesView').value);
    }).damId;
  }

  generateForm() {
    this.workflowService.getJsonSchemaFromWdl(this.form.get('wdl').value)
      .subscribe(({ input_schema: inputSchema }) => {
        this.inputSchema = inputSchema;
      });
  }

  inputFormChange(inputs) {
    this.form.get('inputs').setValue(inputs);
  }

}

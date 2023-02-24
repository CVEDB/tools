<template>
  <!-- notice dialogRef here -->
  <q-dialog ref="dialogRef" @hide="onDialogHide" :persistent="unsavedChanges">
    <q-card class="q-dialog-plugin">
      <q-card-section class="bg-primary text-white text-center">
        <div class="text-h6">Edit CVEDB</div>
      </q-card-section>

      <q-separator />

      <q-card-section style="overflow: auto; max-height: 80vh;">
        <q-toggle
          v-model="jsonEditMode"
          label="JSON Edit Mode"
        />
        <q-btn
          @click="resetValues"
          :disabled="!unsavedChanges"
          class="float-right"
          color="secondary"
          label="Undo Changes"
        />

        <template v-if="jsonEditMode">
          <q-input
            v-model="cvedbJson"
            filled
            autogrow
            label="CVEDB JSON"
          />
        </template>

        <template v-else>
          <q-input
            v-model="cvedbDescription"
            filled
            autogrow
            label="Description"
          />
          <hr>
          <template v-for="(reference, index) in cvedbReferences" :key="reference.id">
            <q-select
              v-model="reference.type"
              :options="referenceOptions"
              filled
              label="Type"
            />
            <q-input
              v-model="reference.other_type"
              filled
              class="q-mt-sm"
              label="Other Type"
              v-if="reference.type === 'OTHER'"
            />
            <br>
            <q-input
              v-model="reference.url"
              filled
              label="URL"
            />
            <br>
            <q-btn
              color="negative"
              icon="fa fa-minus"
              label="Remove Reference"
              @click="removeReference(index)"
            />
            <hr>
          </template>
          <q-btn
            color="positive"
            icon="fa fa-plus"
            label="Add Reference"
            @click="addReference"
          />
        </template>
      </q-card-section>

      <q-card-actions align="right">
        <q-btn flat label="Cancel" color="grey" v-close-popup />
        <q-btn flat label="Save Changes" color="primary" @click="saveChanges" :disabled="!unsavedChanges" />
      </q-card-actions>
    </q-card>
  </q-dialog>
</template>

<script>
import { useDialogPluginComponent, useQuasar } from 'quasar'
import { computed, ref, watch, unref } from 'vue'
import { api } from 'boot/axios'

import { errorNotification } from '../misc/ErrorNotification'

import _ from 'lodash'

export default {
  name: 'EditDialog',

  props: {
    cvedb_json: {
      type: String,
      required: true
    },
    identifier: {
      type: String,
      required: true
    }
  },

  emits: [
    // REQUIRED; need to specify some events that your
    // component will emit through useDialogPluginComponent()
    ...useDialogPluginComponent.emits
  ],

  setup (props, { emit }) {
    // REQUIRED; must be called inside of setup()
    const { dialogRef, onDialogHide, onDialogOK, onDialogCancel } = useDialogPluginComponent()
    // dialogRef      - Vue ref to be applied to QDialog
    // onDialogHide   - Function to be used as handler for @hide on QDialog
    // onDialogOK     - Function to call to settle dialog with "ok" outcome
    //                    example: onDialogOK() - no payload
    //                    example: onDialogOK({ /*.../* }) - with payload
    // onDialogCancel - Function to call to settle dialog with "cancel" outcome

    const $q = useQuasar()

    const cvedbJson = ref(props.cvedb_json)
    const jsonEditMode = ref(false)

    let cvedbJsonObject = JSON.parse(cvedbJson.value)
    const cvedbOriginalDescription = ref('')
    const cvedbOriginalReferences = ref([])

    if(cvedbJsonObject.CVEDB !== undefined) {
      cvedbOriginalDescription.value = cvedbJsonObject.CVEDB.description

      if(isArrayOfStrings(cvedbJsonObject.CVEDB.references)) {
        for(const reference of cvedbJsonObject.CVEDB.references) {
          cvedbOriginalReferences.value.push({ type: 'WEB', url: reference });
        }
      } else {
        for(const reference of cvedbJsonObject.CVEDB.references) {
          cvedbOriginalReferences.value.push({ type: reference.type, url: reference.url });
        }
      }
    } else if(cvedbJsonObject.cvedb !== undefined) {
      cvedbOriginalDescription.value = cvedbJsonObject.cvedb.description

      if(isArrayOfStrings(cvedbJsonObject.cvedb.references)) {
        for(const reference of cvedbJsonObject.cvedb.references) {
          cvedbOriginalReferences.value.push({ type: 'WEB', url: reference });
        }
      } else {
        for(const reference of cvedbJsonObject.cvedb.references) {
          cvedbOriginalReferences.value.push({ type: reference.type, url: reference.url });
        }
      }
    }

    const cvedbDescription = ref(cvedbOriginalDescription.value)
    // NOTE: Have I mentioned I HATE JavaScript with a FIERY PASSION?
    // (Needing to use JSON to pass an array by value is so incredibly dumb)
    const cvedbReferences = ref(JSON.parse(JSON.stringify(cvedbOriginalReferences.value)))
    const referenceOptions = [
      'ADVISORY',
      'ARTICLE',
      'REPORT',
      'FIX',
      'GIT',
      'PACKAGE',
      'EVIDENCE',
      'WEB',
      'OTHER'
    ]

    const unsavedChanges = computed(
      () => {
        if(jsonEditMode.value) {
          return (props.cvedb_json !== cvedbJson.value)
        } else {
          return (
            (cvedbOriginalDescription.value !== cvedbDescription.value) ||
            (!(_.isEqual(cvedbOriginalReferences.value, cvedbReferences.value)))
          )
        }
      }
    )

    function removeReference(index) {
      cvedbReferences.value.splice(index, 1)
    }

    function addReference() {
      cvedbReferences.value.push({ type: 'WEB', url: '' })
    }

    function resetValues() {
      cvedbJson.value = props.cvedb_json
      cvedbDescription.value = cvedbOriginalDescription.value
      cvedbReferences.value = JSON.parse(JSON.stringify(cvedbOriginalReferences.value))
    }

    // console.log(unsavedChanges.value)

    watch(
      () => cvedbReferences.value,
      (newValue) => {
        console.log(unsavedChanges.value)
      }
    )

    function isArrayOfStrings(value) {
      return (
        Array.isArray(value) &&
        value.every(
          (el) => typeof el === 'string'
        )
      )
    }

    function saveChanges() {
      let fileContent = '';
      try {
        // Force reformatting of the JSON string, as well as check validity.
        if(jsonEditMode.value) {
          fileContent = JSON.stringify(JSON.parse(cvedbJson.value), null, 2);
        } else {
          let tempGsdJson = JSON.parse(props.cvedb_json);
          let cvedbLowercase = (tempGsdJson.cvedb !== undefined);
          let tempReferences = JSON.parse(JSON.stringify(cvedbReferences.value))

          tempReferences.forEach(
            (reference) => {
              if(reference.type === 'OTHER' && reference.other_type !== undefined) {
                reference.type = reference.other_type
              }
              delete(reference.other_type)
            }
          )

          if(cvedbLowercase) {
            tempGsdJson.cvedb.description = cvedbDescription.value;
            tempGsdJson.cvedb.references = JSON.parse(JSON.stringify(tempReferences))
          } else {
            tempGsdJson.CVEDB.description = cvedbDescription.value;
            tempGsdJson.CVEDB.references = JSON.parse(JSON.stringify(tempReferences))
          }

          fileContent = JSON.stringify(tempGsdJson, null, 2);
        }
        api.patch('/update-cvedb', {
          identifier: props.identifier,
          file_content: fileContent + '\n'
        }).then(
          (response) => {
            const redirectWindow = window.open(
              response.data.redirect_url,
              '_blank'
            )
            if(!redirectWindow) {
              $q.notify({
                color: 'negative',
                position: 'top',
                message: 'Please allow pop-ups to open GitHub Pull Request',
                icon: 'report_problem'
              })
            }
            $q.notify({
              color: 'positive',
              position: 'top',
              message: 'Changes saved!',
              icon: 'published_with_changes'
            })
            onCancelClick()
          },
          (error) => {
            errorNotification(error, 'Failed to update CVEDB')
          }
        )
      } catch(error) {
        errorNotification(error, 'Failed to save changes')
      }
    }

    return {
      // Custom stuff
      cvedbJson,
      saveChanges,
      unsavedChanges,
      jsonEditMode,
      cvedbDescription,
      cvedbReferences,
      referenceOptions,
      removeReference,
      addReference,
      resetValues,

      // This is REQUIRED;
      // Need to inject these (from useDialogPluginComponent() call)
      // into the vue scope for the vue html template
      dialogRef,
      onDialogHide,

      // other methods that we used in our vue html template;
      // these are part of our example (so not required)
      onOKClick () {
        // on OK, it is REQUIRED to
        // call onDialogOK (with optional payload)
        onDialogOK()
        // or with payload: onDialogOK({ ... })
        // ...and it will also hide the dialog automatically
      },

      // we can passthrough onDialogCancel directly
      onCancelClick: onDialogCancel
    }
  }
}
</script>

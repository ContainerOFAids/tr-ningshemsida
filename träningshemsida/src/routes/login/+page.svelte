<script lang="ts">
    import { enhance } from "$app/forms";
    import type { ActionData } from "./$types";
    export let form: ActionData;
</script>
<form method="post" action="?/login" use:enhance>
    <div class="box-menu">
        <label for="name"></label>
        <input type="text" name="username" class="input-login" placeholder="username" required>
        <input type="password" placeholder="password" class="input-login" required name="password">
        <button class="button-login">login</button>
        <!-- <button class="button-login">Register</button> -->

    
    
        <!-- {#if form?.username}
            <span style="color: red;">{form.username}</span>
        {/if}
            
        {#if form?.password}
            <span style="color: red;">{form.password}</span>
        {/if} -->
    </div>
</form>
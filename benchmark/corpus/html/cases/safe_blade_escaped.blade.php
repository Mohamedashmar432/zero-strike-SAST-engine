@extends('layouts.app')

@section('content')
{{-- ZS-HTML-029 look-alike: escaped output, an encoder, a constant. --}}
@foreach ($comments as $comment)
    <div class="body">{{ $comment->body }}</div>
    <div class="note">{!! e($comment->note) !!}</div>
@endforeach
<p>Sorted by: <?= e($_GET['sort'] ?? 'date') ?></p>
<p>{!! '<hr>' !!}</p>
@endsection
